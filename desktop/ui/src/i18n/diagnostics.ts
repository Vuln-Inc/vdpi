import type { DiagnosticCheckItem } from "../types";
import { createTranslator, type ResolvedLanguage } from "./context";
import { localizeActionMessage } from "./shell";

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
    actionRepairInInstallation: "Repair in Installation",
    actionOpenDnsRules: "Open DNS & Rules",
    actionGoOverview: "Go to Overview",
    actionSwitchingProxy: "Switching to Proxy...",
    actionSwitchProxy: "Switch to Proxy",
    actionOpenSettings: "Open Settings",
    actionOpenAppFolder: "Open App Folder",
    actionOpenLogs: "Open Logs",
    actionResetNetwork: "Reset Network",
    actionResettingNetwork: "Resetting...",
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
    stateNotInstalled: "Servis kurulu değil",
    stateRunning: "Servis çalışıyor",
    stateStopped: "Servis durduruldu",
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
      "Arka plan servisi sağlığını, yapılandırma durumunu ve çalışma dosyalarını inceler.",
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
    actionRepairInInstallation: "Kurulumda Onar",
    actionOpenDnsRules: "DNS ve Kuralları Aç",
    actionGoOverview: "Genel Bakışa Git",
    actionSwitchingProxy: "Proxy'ye Geçiliyor...",
    actionSwitchProxy: "Proxy'ye Geç",
    actionOpenSettings: "Ayarları Aç",
    actionOpenAppFolder: "Uygulama Klasörünü Aç",
    actionOpenLogs: "Günlükleri Aç",
    actionResetNetwork: "Ağı Sıfırla",
    actionResettingNetwork: "Sıfırlanıyor...",
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
      "Ağ ortamınızı ve vdpi kurulumunuzu doğrulamak için hızlı bir uçtan uca sağlık denetimi çalıştırın. Denetimler tamamen salt okunurdur; yapılandırmayı, rotaları veya çalışan servisleri değiştirmez.",
    readonlyBadge: "%100 salt okunur ve güvenli",
    ariaChecksIncluded: "Dahil edilen denetimler",
};

export const DIAGNOSTICS_STRINGS: {
  en: Record<DiagnosticsStringKey, string>;
  tr: Record<DiagnosticsStringKey, string>;
} = { en, tr };

export const tDiagnostics = createTranslator(DIAGNOSTICS_STRINGS);

const CHECK_ID_KEY_MAP: Record<string, DiagnosticsStringKey> = {
  vpn_coexistence: "probeVpnLabel",
  vpn: "probeVpnLabel",
  wintun_driver: "probeWintunLabel",
  wintun: "probeWintunLabel",
  dns_resolution: "probeDnsLabel",
  dns: "probeDnsLabel",
  discord_gateway: "probeDiscordLabel",
  discord: "probeDiscordLabel",
  roblox_clientsettings: "probeRobloxLabel",
  roblox: "probeRobloxLabel",
  service_hygiene: "probeRuntimeLabel",
  runtime: "probeRuntimeLabel",
};

const CHECK_NAME_KEY_MAP: Record<string, DiagnosticsStringKey> = {
  "vpn coexistence": "probeVpnLabel",
  "wintun driver": "probeWintunLabel",
  "dns / doh": "probeDnsLabel",
  "encrypted dns (doh)": "checkEncryptedDns",
  "upstream dns (udp)": "checkUpstreamDns",
  discord: "probeDiscordLabel",
  "discord web & gateway": "probeDiscordLabel",
  roblox: "probeRobloxLabel",
  "roblox clientsettings": "probeRobloxLabel",
  "runtime hygiene": "probeRuntimeLabel",
  "service hygiene": "probeRuntimeLabel",
  "service & runtime hygiene": "probeRuntimeLabel",
};

export function localizeCheckName(
  lang: ResolvedLanguage,
  check: DiagnosticCheckItem,
): string {
  if (lang === "en") return check.name;
  const id = check.id.trim().toLowerCase();
  const normalizedName = check.name.trim().toLowerCase();

  if (id === "dns_resolution" || id === "dns") {
    if (normalizedName.includes("doh") || normalizedName.includes("encrypted")) {
      return tDiagnostics(lang, "checkEncryptedDns");
    }
    if (normalizedName.includes("udp")) {
      return tDiagnostics(lang, "checkUpstreamDns");
    }
    return tDiagnostics(lang, "probeDnsLabel");
  }

  const idKey = CHECK_ID_KEY_MAP[id];
  if (idKey) {
    return tDiagnostics(lang, idKey);
  }

  const nameKey = CHECK_NAME_KEY_MAP[normalizedName];
  return nameKey ? tDiagnostics(lang, nameKey) : check.name;
}

function localizeSplitSummaryTr(summary: string): string {
  if (summary === "All apps") {
    return "Tüm uygulamalar";
  }
  const excludeMatch = /^Exclude \((\d+) apps?\)$/.exec(summary);
  if (excludeMatch) {
    return `Hariç Tut (${excludeMatch[1]} uygulama)`;
  }
  const includeMatch = /^Include \((\d+) apps?\)$/.exec(summary);
  if (includeMatch) {
    return `Dahil Et (${includeMatch[1]} uygulama)`;
  }
  return summary;
}

function localizeVpnCoexistenceModeTr(mode: string): string {
  switch (mode.trim().toLowerCase()) {
    case "auto-yield":
    case "auto_yield":
      return "Oto-duraklat";
    case "warn":
      return "Uyar";
    case "off":
      return "Kapalı";
    default:
      return mode;
  }
}

function localizeServiceStateTr(state: string, capitalize = false): string {
  switch (state.trim().toLowerCase()) {
    case "running":
      return capitalize ? "Çalışıyor" : "çalışıyor";
    case "stopped":
      return capitalize ? "Durduruldu" : "durduruldu";
    case "not installed":
    case "not_installed":
      return capitalize ? "Kurulu değil" : "kurulu değil";
    default:
      return state;
  }
}

function localizeHttpPathDescTr(text: string): string {
  if (text === "Via active TUN engine") {
    return "Etkin TUN motoru üzerinden";
  }
  if (text === "Direct (vdpi not running - anti-DPI bypass not tested)") {
    return "Doğrudan (vdpi çalışmıyor - DPI aşımı test edilmedi)";
  }
  const viaProxy = /^Via local proxy (.+)$/.exec(text);
  if (viaProxy) {
    return `Yerel proxy (${viaProxy[1]}) üzerinden`;
  }
  const invalidProxy = /^invalid local proxy URL: (.+)$/.exec(text);
  if (invalidProxy) {
    return `Geçersiz yerel proxy URL'si: ${invalidProxy[1]}`;
  }
  return text;
}

function localizeServiceSummarySegmentTr(segment: string): string {
  if (segment === "TUN active") return "TUN etkin";
  if (segment === "Proxy active") return "Proxy etkin";
  if (segment === "config warning") return "yapılandırma uyarısı";
  if (segment === "Bundled vdpi CLI missing") return "Paketli vdpi CLI eksik";
  if (segment === "Service not installed") return "Servis kurulu değil";
  if (segment === "Service stopped (standby)") return "Servis durduruldu (beklemede)";
  if (segment === "Service not installed (standby)") {
    return "Servis kurulu değil (beklemede)";
  }
  if (segment === "Background service is not installed") {
    return "Arka plan servisi kurulu değil";
  }
  if (
    segment === "Background service needs repair" ||
    segment === "Service installation needs repair" ||
    segment === "Service needs repair"
  ) {
    return "Arka plan servisinin onarılması gerekiyor";
  }

  const repairWithReason = /^Background service needs repair \((.+)\)$/.exec(
    segment,
  );
  if (repairWithReason) {
    return `Arka plan servisinin onarılması gerekiyor (${repairWithReason[1]})`;
  }

  const tunActive = /^TUN active \((.+)\)$/.exec(segment);
  if (tunActive) {
    return `TUN etkin (${tunActive[1]})`;
  }

  const proxyActive = /^Proxy active \((.+)\)$/.exec(segment);
  if (proxyActive) {
    return `Proxy etkin (${proxyActive[1]})`;
  }

  const engineMismatch =
    /^Engine mismatch: configured (TUN|Proxy), live (TUN|Proxy)$/.exec(segment);
  if (engineMismatch) {
    return `Motor uyumsuzluğu: yapılandırılan ${engineMismatch[1]}, çalışan ${engineMismatch[2]}`;
  }

  const versionMismatch =
    /^Version mismatch: installed (v?[^,]+), live (v?.+)$/.exec(segment);
  if (versionMismatch) {
    return `Sürüm uyumsuzluğu: kurulu ${versionMismatch[1]}, çalışan ${versionMismatch[2]}`;
  }

  const orphaned = /^Orphaned live process \(service (.+)\)$/.exec(segment);
  if (orphaned) {
    return `Sahipsiz çalışan süreç (servis ${localizeServiceStateTr(orphaned[1])})`;
  }

  const elevatedMem = /^elevated memory \((.+)\)$/.exec(segment);
  if (elevatedMem) {
    return `yüksek bellek kullanımı (${elevatedMem[1]})`;
  }

  const tcpFlows = /^(\d+) TCP flows?$/.exec(segment);
  if (tcpFlows) {
    return `${tcpFlows[1]} TCP akışı`;
  }

  const runningYielded =
    /^(TUN|Proxy) service running \(protection paused - VPN conflict: (.+)\)$/.exec(
      segment,
    );
  if (runningYielded) {
    return `${runningYielded[1]} servisi çalışıyor (koruma duraklatıldı - VPN çakışması: ${runningYielded[2]})`;
  }

  const runningNoLive =
    /^(TUN|Proxy) service running \(live telemetry unavailable\)$/.exec(
      segment,
    );
  if (runningNoLive) {
    return `${runningNoLive[1]} servisi çalışıyor (canlı telemetri kullanılamıyor)`;
  }

  const installedPaused =
    /^Service installed \((TUN|Proxy)\) but protection is paused$/.exec(
      segment,
    );
  if (installedPaused) {
    return `Servis kurulu (${installedPaused[1]}) ancak koruma duraklatıldı`;
  }

  return segment;
}

function localizeServiceDetailSegmentTr(segment: string): string {
  if (segment === "restart service to apply configured engine") {
    return "yapılandırılan motoru uygulamak için servisi yeniden başlatın";
  }
  if (segment === "restart service to load installed version") {
    return "kurulu sürümü yüklemek için servisi yeniden başlatın";
  }
  if (
    segment ===
    "Background service reports Running, but the health endpoint returned no active engine."
  ) {
    return "Arka plan servisi çalışıyor görünüyor ancak sağlık uç noktası etkin bir motor döndürmedi.";
  }
  if (
    segment ===
    "The bundled vdpi CLI engine binary was not found in the application directory. Reinstall vdpi Desktop, extract all files from the archive, or check antivirus quarantine before installing the service."
  ) {
    return "Paketli vdpi CLI motor ikili dosyası uygulama klasöründe bulunamadı. Servisi kurmadan önce vdpi Desktop uygulamasını yeniden kurun, arşivdeki tüm dosyaları çıkarın veya antivirüs karantinasını kontrol edin.";
  }
  if (
    segment ===
    "Checks ran over your direct connection until the vdpi service is installed and active."
  ) {
    return "vdpi servisi kurulup etkinleşene kadar denetimler doğrudan bağlantınız üzerinden çalıştırıldı.";
  }
  if (
    segment ===
    "Install the background service from Settings to enable protection."
  ) {
    return "Korumayı etkinleştirmek için Kurulum sekmesinden arka plan servisini kurun.";
  }
  if (
    segment ===
    "Install the background service from Installation to enable protection."
  ) {
    return "Korumayı etkinleştirmek için Kurulum sekmesinden arka plan servisini kurun.";
  }
  if (
    segment ===
    "Click Connect on Overview to resume live anti-DPI protection."
  ) {
    return "Canlı DPI aşımı korumasını sürdürmek için Genel Bakış sekmesinde Bağlan'a tıklayın.";
  }

  if (
    /^(?:The )?(?:background )?service (?:registration|installation|binary).*(?:repair|reinstall).*$/i.test(
      segment,
    )
  ) {
    return "Arka plan servis kaydı veya kurulu ikili dosya eksik görünüyor. Yapılandırmanızı kaybetmeden vdpi'yi geri yüklemek için Kurulum sekmesinden Onar / Yeniden Kur seçeneğini çalıştırın.";
  }

  if (
    /^Installed (?:vdpi |CLI )?(?:engine )?binary (?:is missing|could not be verified on disk)/i.test(
      segment,
    )
  ) {
    return "Servis kayıtlıyken kurulu ikili dosya diskte doğrulanamadı. Arka plan servisini geri yüklemek için Kurulum sekmesinden Onar / Yeniden Kur seçeneğini çalıştırın.";
  }

  const liveWhileState =
    /^live engine running while service state is (.+)$/.exec(segment);
  if (liveWhileState) {
    return `servis durumu ${localizeServiceStateTr(liveWhileState[1], true)} iken canlı motor çalışıyor`;
  }

  const rssThreshold = /^RSS exceeds (\d+) MB threshold$/.exec(segment);
  if (rssThreshold) {
    return `RSS bellek kullanımı ${rssThreshold[1]} MB eşiğini aşıyor`;
  }

  const configWarn = /^Config warning: (.+)$/.exec(segment);
  if (configWarn) {
    return `Yapılandırma uyarısı: ${configWarn[1]}`;
  }

  const yieldedDetail =
    /^Background service is running, but protection is yielded while active VPN \((.+)\) is connected\.$/.exec(
      segment,
    );
  if (yieldedDetail) {
    return `Arka plan servisi çalışıyor ancak etkin VPN (${yieldedDetail[1]}) bağlıyken koruma duraklatıldı.`;
  }

  const configuredStopped =
    /^Configured engine: (TUN|Proxy)\. Start vdpi to enable protection\.$/.exec(
      segment,
    );
  if (configuredStopped) {
    return `Yapılandırılan motor: ${configuredStopped[1]}. Korumayı etkinleştirmek için vdpi'yi başlatın.`;
  }

  const desyncMode = /^desync (.+)$/.exec(segment);
  if (desyncMode) {
    return `desync modu: ${desyncMode[1]}`;
  }

  const adapterVia = /^Adapter (.+?) via (.+)$/.exec(segment);
  if (adapterVia) {
    return `Bağdaştırıcı ${adapterVia[1]} (${adapterVia[2]} üzerinden)`;
  }

  const adaptiveStage = /^adaptive stage (.+)$/.exec(segment);
  if (adaptiveStage) {
    return `uyarlanabilir aşama: ${adaptiveStage[1]}`;
  }

  return localizeActionMessage("tr", segment);
}

export function localizeCheckTarget(
  lang: ResolvedLanguage,
  target: string,
): string {
  const trimmed = target.trim();
  if (!trimmed || lang === "en") return trimmed;
  switch (trimmed.toLowerCase()) {
    case "routing table & adapters":
      return "Yönlendirme tablosu ve bağdaştırıcılar";
    case "routing & split rules":
      return "Yönlendirme ve bölünmüş kurallar";
    case "tun service":
      return "TUN servisi";
    case "proxy service":
      return "Proxy servisi";
    default:
      return trimmed;
  }
}

export function localizeCheckSummary(
  lang: ResolvedLanguage,
  check: { id: string; summary: string },
): string {
  if (lang === "en") return check.summary;
  const raw = check.summary.trim();
  if (!raw) return check.summary;

  const id = check.id.trim().toLowerCase();

  // Check 1: VPN Coexistence
  if (id === "vpn_coexistence" || id === "vpn") {
    if (raw === "VPN detection task failed") {
      return "VPN algılama görevi başarısız oldu";
    }
    if (raw === "VPN detection timed out") {
      return "VPN algılama zaman aşımına uğradı";
    }
    const fullOff =
      /^Full-tunnel VPN active while coexistence is off: (.+)$/.exec(raw);
    if (fullOff) {
      return `VPN Uyumluluğu kapalıyken tam tünelli VPN etkin: ${fullOff[1]}`;
    }
    const vpnCheckOff = /^VPN check off · (.+)$/.exec(raw);
    if (vpnCheckOff) {
      return `VPN denetimi kapalı · ${localizeSplitSummaryTr(vpnCheckOff[1])}`;
    }
    const fullConflict = /^Full-tunnel VPN conflict: (.+)$/.exec(raw);
    if (fullConflict) {
      return `Tam tünelli VPN çakışması: ${fullConflict[1]}`;
    }
    const splitOverlay = /^Split-tunnel overlay \((.+)\) · (.+)$/.exec(raw);
    if (splitOverlay) {
      return `Bölünmüş tünel katmanı (${splitOverlay[1]}) · ${localizeSplitSummaryTr(splitOverlay[2])}`;
    }
    const noConflict = /^No VPN conflict · (.+)$/.exec(raw);
    if (noConflict) {
      return `VPN çakışması yok · ${localizeSplitSummaryTr(noConflict[1])}`;
    }
    const activeVpnMock = /^Active VPN detected \((.+)\) · (.+)$/.exec(raw);
    if (activeVpnMock) {
      return `Etkin VPN algılandı (${activeVpnMock[1]}) · ${localizeSplitSummaryTr(activeVpnMock[2])}`;
    }
  }

  // Check 2: Wintun Driver
  if (id === "wintun_driver" || id === "wintun") {
    const verifiedTun =
      /^wintun\.dll v([^\s]+) SHA-256 verified \(TUN active\)$/.exec(raw);
    if (verifiedTun) {
      return `wintun.dll v${verifiedTun[1]} SHA-256 doğrulandı (TUN etkin)`;
    }
    const verifiedDisk =
      /^wintun\.dll v([^\s]+) SHA-256 verified on disk$/.exec(raw);
    if (verifiedDisk) {
      return `wintun.dll v${verifiedDisk[1]} diskte SHA-256 doğrulandı`;
    }
    if (raw === "wintun.dll corrupted or mismatched (required for TUN)") {
      return "wintun.dll bozuk veya eşleşmiyor (TUN için gerekli)";
    }
    if (raw === "wintun.dll missing or invalid (required for TUN)") {
      return "wintun.dll eksik veya geçersiz (TUN için gerekli)";
    }
    if (
      raw === "wintun.dll corrupted or mismatched (Proxy ok; needed for TUN)"
    ) {
      return "wintun.dll bozuk veya eşleşmiyor (Proxy sorunsuz; TUN için gerekli)";
    }
    if (raw === "wintun.dll missing or invalid (Proxy ok; needed for TUN)") {
      return "wintun.dll eksik veya geçersiz (Proxy sorunsuz; TUN için gerekli)";
    }
    if (raw === "wintun.dll verified and ready for TUN adapter") {
      return "wintun.dll doğrulandı ve TUN bağdaştırıcısı için hazır";
    }
    if (raw === "wintun.dll available (not required in Proxy mode)") {
      return "wintun.dll mevcut (Proxy modunda gerekli değil)";
    }
    if (raw === "wintun.dll missing") {
      return "wintun.dll eksik";
    }
  }

  // Check 3: DNS / DoH Resolution
  if (id === "dns_resolution" || id === "dns") {
    if (raw === "No IP addresses returned") {
      return "Hiçbir IP adresi döndürülmedi";
    }
    const initFailed = /^Resolver init failed \((.+)\)$/.exec(raw);
    if (initFailed) {
      return `Çözümleyici başlatılamadı (${initFailed[1]})`;
    }
    const hostResolved = /^(.+) resolved \((\d+) IPs?\)$/.exec(raw);
    if (hostResolved) {
      return `${hostResolved[1]} çözümlendi (${hostResolved[2]} IP)`;
    }
    const lookupFailed = /^(DoH|UDP) lookup failed$/.exec(raw);
    if (lookupFailed) {
      return `${lookupFailed[1]} sorgusu başarısız oldu`;
    }
    const lookupTimedOut = /^(DoH|UDP) lookup timed out$/.exec(raw);
    if (lookupTimedOut) {
      return `${lookupTimedOut[1]} sorgusu zaman aşımına uğradı`;
    }
    const resolvedViaMock = /^Resolved via (DoH|UDP) \((.+)\)$/.exec(raw);
    if (resolvedViaMock) {
      return `${resolvedViaMock[1]} ile çözümlendi (${resolvedViaMock[2]})`;
    }
  }

  // Checks 4 & 5: HTTP Reachability (Discord & Roblox)
  if (
    id === "discord_gateway" ||
    id === "discord" ||
    id === "roblox_clientsettings" ||
    id === "roblox"
  ) {
    if (raw === "Reachability check failed") {
      return "Erişilebilirlik denetimi başarısız oldu";
    }
    if (raw === "HTTPS client unavailable") {
      return "HTTPS istemcisi kullanılamıyor";
    }
    if (raw === "TLS 1.3 handshake succeeded via adaptive bypass") {
      return "Uyarlanabilir aşım ile TLS 1.3 el sıkışması başarılı";
    }
    if (raw === "Protection service not installed; bypass check skipped") {
      return "Koruma servisi kurulu değil; aşım denetimi atlandı";
    }
    if (raw === "Protection paused; direct probe without DPI bypass") {
      return "Koruma duraklatıldı; DPI aşımı olmadan doğrudan denetim";
    }
    const directHttp =
      /^Reachable directly \(HTTP (\d+)\) - bypass not tested$/.exec(raw);
    if (directHttp) {
      return `Doğrudan erişilebilir (HTTP ${directHttp[1]}) - aşım test edilmedi`;
    }
    const reachableHttp = /^Reachable \(HTTP (\d+)\)$/.exec(raw);
    if (reachableHttp) {
      return `Erişilebilir (HTTP ${reachableHttp[1]})`;
    }
    const redirectHttp =
      /^Unexpected redirect \(HTTP (\d+), possible captive portal\)$/.exec(raw);
    if (redirectHttp) {
      return `Beklenmeyen yönlendirme (HTTP ${redirectHttp[1]}, olası captive portal)`;
    }
    const unexpectedHttp = /^TLS verified, unexpected HTTP (\d+)$/.exec(raw);
    if (unexpectedHttp) {
      return `TLS doğrulandı, beklenmeyen HTTP ${unexpectedHttp[1]}`;
    }
    const timedOut = /^Timed out after (\d+)s$/.exec(raw);
    if (timedOut) {
      return `${timedOut[1]} sn sonra zaman aşımına uğradı`;
    }
  }

  // Check 6: Service & Runtime Hygiene (supports composite ` · ` segments)
  if (id === "service_hygiene" || id === "runtime") {
    const segments = raw.split(" · ");
    const translated = segments.map((seg) =>
      localizeServiceSummarySegmentTr(seg.trim()),
    );
    return translated.join(" · ");
  }

  return localizeActionMessage("tr", raw);
}

export function localizeCheckDetail(
  lang: ResolvedLanguage,
  check: { id: string; detail: string },
): string {
  if (lang === "en") return check.detail;
  const raw = check.detail.trim();
  if (!raw) return check.detail;

  const id = check.id.trim().toLowerCase();

  // Check 1: VPN Coexistence
  if (id === "vpn_coexistence" || id === "vpn") {
    if (raw === "VPN coexistence detection is disabled in configuration.") {
      return "Yapılandırmada VPN Uyumluluğu algılaması devre dışı.";
    }
    if (
      raw ===
      "Warning: empty Include protects no apps until at least one application is added."
    ) {
      return "Uyarı: boş Dahil Et listesi en az bir uygulama eklenene kadar hiçbir uygulamayı korumaz.";
    }
    const timeoutDetail =
      /^Adapter & route probe did not complete within (\d+)s$/.exec(raw);
    if (timeoutDetail) {
      return `Bağdaştırıcı ve yönlendirme denetimi ${timeoutDetail[1]} sn içinde tamamlanamadı`;
    }
    const offConflictDetail =
      /^VPN coexistence detection is disabled in configuration - active full-tunnel VPN may conflict with vdpi · Split tunnel: (.+)$/.exec(
        raw,
      );
    if (offConflictDetail) {
      return `Yapılandırmada VPN Uyumluluğu algılaması devre dışı - etkin tam tünelli VPN, vdpi ile çakışabilir · Bölünmüş Tünel: ${localizeSplitSummaryTr(offConflictDetail[1])}`;
    }
    const offSplitOverlay =
      /^VPN coexistence detection is disabled \(split overlay: (.+)\)\.$/.exec(
        raw,
      );
    if (offSplitOverlay) {
      return `VPN Uyumluluğu algılaması devre dışı (bölünmüş katman: ${offSplitOverlay[1]}).`;
    }
    const coexAndSplit = /^Coexistence: (.+?) · Split tunnel: (.+)$/.exec(raw);
    if (coexAndSplit) {
      return `VPN Uyumluluğu: ${localizeVpnCoexistenceModeTr(coexAndSplit[1])} · Bölünmüş Tünel: ${localizeSplitSummaryTr(coexAndSplit[2])}`;
    }
    const overlayNoDefault =
      /^Overlay does not own the global default route · Coexistence: (.+)$/.exec(
        raw,
      );
    if (overlayNoDefault) {
      return `Katman genel varsayılan rotayı devralmıyor · VPN Uyumluluğu: ${localizeVpnCoexistenceModeTr(overlayNoDefault[1])}`;
    }
    const coexOnly = /^Coexistence: (.+)$/.exec(raw);
    if (coexOnly) {
      return `VPN Uyumluluğu: ${localizeVpnCoexistenceModeTr(coexOnly[1])}`;
    }
    const mockPolicy = /^VPN coexistence policy: (.+)$/.exec(raw);
    if (mockPolicy) {
      return `VPN Uyumluluğu ilkesi: ${localizeVpnCoexistenceModeTr(mockPolicy[1])}`;
    }
    const mockDetail =
      /^VPN coexistence: (.+?) · (\d+) bypass \/ (\d+) include domains$/.exec(
        raw,
      );
    if (mockDetail) {
      return `VPN Uyumluluğu: ${localizeVpnCoexistenceModeTr(mockDetail[1])} · ${mockDetail[2]} hariç tutma / ${mockDetail[3]} dahil etme alan adı`;
    }
  }

  // Check 2: Wintun Driver
  if (id === "wintun_driver" || id === "wintun") {
    const segments = raw.split(" · ").map((seg) => {
      const s = seg.trim();
      if (s === "Proxy mode active - TUN adapter load not tested") {
        return "Proxy modu etkin - TUN bağdaştırıcısı yüklemesi test edilmedi";
      }
      if (
        s ===
        "Service not running - driver load and adapter creation not tested"
      ) {
        return "Servis çalışmıyor - sürücü yüklemesi ve bağdaştırıcı oluşturma test edilmedi";
      }
      if (
        s ===
        "Extract all files from the release archive (keep wintun.dll beside vdpi.exe)."
      ) {
        return "Sürüm arşivindeki tüm dosyaları çıkarın (wintun.dll dosyasını vdpi.exe yanında tutun).";
      }
      if (
        s ===
        "Extract all files from the zip (keep wintun.dll beside vdpi.exe)."
      ) {
        return "Zip arşivindeki tüm dosyaları çıkarın (wintun.dll dosyasını vdpi.exe yanında tutun).";
      }
      return localizeActionMessage("tr", s);
    });
    return segments.join(" · ");
  }

  // Check 3: DNS / DoH Resolution
  if (id === "dns_resolution" || id === "dns") {
    const viaWithIp = /^(DoH|UDP) via (.+?) · (.+)$/.exec(raw);
    if (viaWithIp) {
      return `${viaWithIp[2]} üzerinden ${viaWithIp[1]} · ${viaWithIp[3]}`;
    }
    const viaOnly = /^(DoH|UDP) via (.+)$/.exec(raw);
    if (viaOnly) {
      return `${viaOnly[2]} üzerinden ${viaOnly[1]}`;
    }
    const noReply = /^No reply from (.+?) within (\d+)s$/.exec(raw);
    if (noReply) {
      return `${noReply[1]} adresinden ${noReply[2]} sn içinde yanıt alınamadı`;
    }
    const mockDnsDetail =
      /^QUIC blocking: (enabled|disabled) · IPv4-only: (on|off)$/.exec(raw);
    if (mockDnsDetail) {
      const quicState = mockDnsDetail[1] === "enabled" ? "etkin" : "devre dışı";
      const ipv4State = mockDnsDetail[2] === "on" ? "açık" : "kapalı";
      return `QUIC engelleme: ${quicState} · Yalnızca IPv4: ${ipv4State}`;
    }
  }

  // Checks 4 & 5: HTTP Reachability (Discord & Roblox)
  if (
    id === "discord_gateway" ||
    id === "discord" ||
    id === "roblox_clientsettings" ||
    id === "roblox"
  ) {
    if (
      raw === "Start protection to verify live anti-DPI handshake behavior."
    ) {
      return "Canlı DPI aşımı el sıkışma davranışını doğrulamak için korumayı başlatın.";
    }
    const mockEngineStage = /^Engine: (TUN|Proxy) · stage (.+)$/.exec(raw);
    if (mockEngineStage) {
      return `Motor: ${mockEngineStage[1]} · aşama ${mockEngineStage[2]}`;
    }
    const sepIdx = raw.indexOf(" · ");
    if (sepIdx !== -1) {
      const left = raw.slice(0, sepIdx).trim();
      const right = raw.slice(sepIdx + 3).trim();
      return `${localizeHttpPathDescTr(left)} · ${right}`;
    }
    return localizeHttpPathDescTr(raw);
  }

  // Check 6: Service & Runtime Hygiene (supports composite ` · ` segments)
  if (id === "service_hygiene" || id === "runtime") {
    const segments = raw.split(" · ");
    const translated = segments.map((seg) =>
      localizeServiceDetailSegmentTr(seg.trim()),
    );
    return translated.join(" · ");
  }

  return localizeActionMessage("tr", raw);
}
