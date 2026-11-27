import { createTranslator, type ResolvedLanguage } from "./context";

export const LANGUAGE_STORAGE_KEY = "vdpi.gui.language";

const en = {
  // Sidebar
  navAsideAria: "Application navigation",
  navPrimaryAria: "Primary",
  navOverview: "Overview",
  navSplit: "Split Tunnel",
  navDns: "DNS & Rules",
  navDiagnostics: "Diagnostics",
  navSettings: "Settings",
  splitIncludeEmpty: "0 included apps (no apps protected)",
  splitIncludeOne: "1 included app",
  splitIncludeMany: "{count} included apps",
  splitExcludeOne: "1 excluded app",
  splitExcludeMany: "{count} excluded apps",
  statusPaused: "Paused",
  statusPausedTitle: "Protection paused",
  statusSetupNeeded: "Setup needed",
  statusServiceNotInstalledTitle: "Service not installed",
  statusDriverMissing: "Driver missing",
  statusWintunMissingTitle: "wintun.dll missing",
  statusProxyActive: "Proxy · :{port}",
  statusTunActive: "TUN · Active",
  statusPausedVpn: "Paused (VPN)",
  statusYieldedVpnTitle: "Yielded to VPN ({vpn})",
  statusVpnConflictTitle: "VPN conflict detected ({vpn})",
  statusProtectedProxyTitle: "Protected via local proxy on port {port}",
  statusProtectedTunTitle: "Protected via TUN adapter",
  statusStarting: "Starting...",
  statusStartingTitle: "Starting protection service",
  trayUnavailable: "Tray unavailable",
  trayMenuBar: "Menu bar",
  trayOn: "Tray on",
  trayWindowOnly: "Window only",
  trayUnavailableTitle: "System tray is unavailable in this desktop environment",
  trayMenuBarTitle: "vdpi stays available in the menu bar",
  trayOnTitle: "vdpi stays available in the system tray",
  trayWindowOnlyTitle: "Closing the window exits the UI window",

  // ConfirmDialog & ToastStack
  cancel: "Cancel",
  notificationsAria: "Notifications",
  dismissNotificationAria: "Dismiss notification",

  // ThroughputChart
  chartDefaultTitle: "Throughput",
  chartDefaultCaption: "60s window",
  chartDefaultPausedLabel: "Protection paused",
  chartSubChecking: "Reading service status...",
  chartSubSetup: "Complete setup to view live throughput.",
  chartSubStarting: "Waiting for live telemetry...",
  chartSubPaused: "Live throughput resumes when connected.",
  chartWaitingSamples: "Waiting for telemetry samples...",
  chartDownloadTitle: "Download rate",
  chartDownloadSr: "Download ",
  chartUploadTitle: "Upload rate",
  chartUploadSr: "Upload ",
  chartPeak: "Peak",
  chartSvgAriaRunning:
    "Throughput history over 60 samples. Download {rx}, upload {tx}, peak download {peakRx}, peak upload {peakTx}, scale up to {bound}.",
  chartSvgAriaPaused: "Throughput monitoring paused: {label}.",

  // AppErrorBoundary & Shell chrome
  errorBoundaryTitle: "Something went wrong",
  errorBoundaryDesc:
    "An unexpected interface error occurred. The background vdpi service is unaffected.",
  errorBoundaryUnexpected: "Unexpected render error",
  errorBoundaryTryAgain: "Try Again",
  errorBoundaryReload: "Reload Window",
  skipToMain: "Skip to main content",
  workspaceAria: "Workspace",
  backendUnreachableTitle: "Unable to reach vdpi desktop backend",
  settingsLoadErrorTitle: "Unable to load vdpi settings",
  retryAction: "Retry",
  configWarningTitle: "Configuration warning",

  // App toasts & actions
  surfaceMenuBar: "Menu bar",
  surfaceTray: "Tray",
  trayActionCancelled: "{surface} action cancelled.",
  trayActionFailed: "{surface} action failed.",
  actionNeedsRestart: "Action completed. Restart service to apply.",
  protectionCancelled: "Protection change cancelled.",
  protectionUpdateFailed: "Failed to update protection state.",
  protectionNeedsRestart: "Protection updated. Restart service to apply.",
  protectionToggleFailed: "Failed to toggle protection.",
  engineSwitchCancelled: "Engine switch to {engine} cancelled.",
  engineSwitchFailed: "Failed to switch engine to {engine}.",
  engineSwitchNeedsRestart:
    "Switched engine to {engine}. Restart service to apply.",
  engineSwitchSuccess: "Switched engine to {engine}.",
  engineSwitchGenericFailed: "Failed to switch protection engine.",
  installCancelled: "Service installation cancelled.",
  installFailed: "Failed to install background service.",
  installNeedsRestart: "Background service installed. Restart to apply.",
  installSuccess: "Background service installed.",
  folderKindConfig: "config",
  folderKindLogs: "logs",
  folderKindApp: "app",
  openFolderFailed: "Failed to open {kind} folder.",
  refreshStatusFailed: "Could not refresh vdpi status.",
  activityCopied: "Activity log copied to clipboard.",
  activityCopyFailed: "Failed to copy activity log.",
  clipboardUnavailable: "Clipboard API unavailable.",
  copyCommandFailed: "Copy command failed.",

  // App confirm dialogs
  discardDnsTitle: "Discard unsaved DNS & Rules changes?",
  discardSplitTitle: "Discard unsaved split tunnel changes?",
  discardDnsDesc:
    "You have unsaved changes in DNS & Rules. Leaving this tab will discard your edits.",
  discardSplitDesc:
    "You have unsaved changes in Split Tunneling. Leaving this tab will discard your edits.",
  discardConfirm: "Discard & Leave",
  discardCancel: "Stay",
  switchToTunTitle: "Switch to Full-PC (TUN)?",
  switchToTunDesc:
    "Switching to Full-PC (TUN) mode restarts protection, so active connections will reconnect briefly while the virtual adapter starts.{adminNote}",
  switchToTunAdminWindows:
    " A Windows administrator prompt may appear to restart the background service.",
  switchToTunAdminMac:
    " A macOS administrator prompt may appear to restart the background service.",
  switchToTunConfirm: "Switch to Full-PC (TUN)",
} as const;

type ShellDict = Record<keyof typeof en, string>;

const tr: ShellDict = {
  // Sidebar
  navAsideAria: "Uygulama gezinmesi",
  navPrimaryAria: "Ana gezinme",
  navOverview: "Genel Bakış",
  navSplit: "Bölünmüş Tünel",
  navDns: "DNS ve Kurallar",
  navDiagnostics: "Tanılama",
  navSettings: "Ayarlar",
  splitIncludeEmpty: "0 dahil edilen uygulama (hiçbir uygulama korunmuyor)",
  splitIncludeOne: "1 dahil edilen uygulama",
  splitIncludeMany: "{count} dahil edilen uygulama",
  splitExcludeOne: "1 hariç tutulan uygulama",
  splitExcludeMany: "{count} hariç tutulan uygulama",
  statusPaused: "Duraklatıldı",
  statusPausedTitle: "Koruma duraklatıldı",
  statusSetupNeeded: "Kurulum gerekli",
  statusServiceNotInstalledTitle: "Servis kurulu değil",
  statusDriverMissing: "Sürücü eksik",
  statusWintunMissingTitle: "wintun.dll eksik",
  statusProxyActive: "Proxy · :{port}",
  statusTunActive: "TUN · Etkin",
  statusPausedVpn: "Duraklatıldı (VPN)",
  statusYieldedVpnTitle: "VPN'e öncelik verildi ({vpn})",
  statusVpnConflictTitle: "VPN çakışması algılandı ({vpn})",
  statusProtectedProxyTitle: "{port} portundaki yerel proxy ile korunuyor",
  statusProtectedTunTitle: "TUN bağdaştırıcısı ile korunuyor",
  statusStarting: "Başlatılıyor...",
  statusStartingTitle: "Koruma servisi başlatılıyor",
  trayUnavailable: "Tepsi kullanılamıyor",
  trayMenuBar: "Menü çubuğu",
  trayOn: "Tepsi açık",
  trayWindowOnly: "Yalnızca pencere",
  trayUnavailableTitle: "Bu masaüstü ortamında sistem tepsisi kullanılamıyor",
  trayMenuBarTitle: "vdpi menü çubuğunda erişilebilir kalır",
  trayOnTitle: "vdpi sistem tepsisinde erişilebilir kalır",
  trayWindowOnlyTitle: "Pencereyi kapatmak arayüz penceresini kapatır",

  // ConfirmDialog & ToastStack
  cancel: "İptal",
  notificationsAria: "Bildirimler",
  dismissNotificationAria: "Bildirimi kapat",

  // ThroughputChart
  chartDefaultTitle: "Veri Akışı",
  chartDefaultCaption: "60 sn pencere",
  chartDefaultPausedLabel: "Koruma duraklatıldı",
  chartSubChecking: "Servis durumu okunuyor...",
  chartSubSetup: "Canlı veri akışını görmek için kurulumu tamamlayın.",
  chartSubStarting: "Canlı telemetri bekleniyor...",
  chartSubPaused: "Bağlanıldığında canlı veri akışı devam eder.",
  chartWaitingSamples: "Telemetri örnekleri bekleniyor...",
  chartDownloadTitle: "İndirme hızı",
  chartDownloadSr: "İndirme ",
  chartUploadTitle: "Yükleme hızı",
  chartUploadSr: "Yükleme ",
  chartPeak: "Zirve",
  chartSvgAriaRunning:
    "60 örneklik veri akışı geçmişi. İndirme {rx}, yükleme {tx}, zirve indirme {peakRx}, zirve yükleme {peakTx}, üst ölçek {bound}.",
  chartSvgAriaPaused: "Veri akışı izleme duraklatıldı: {label}.",

  // AppErrorBoundary & Shell chrome
  errorBoundaryTitle: "Bir sorun oluştu",
  errorBoundaryDesc:
    "Beklenmeyen bir arayüz hatası oluştu. Arka plandaki vdpi servisi bundan etkilenmedi.",
  errorBoundaryUnexpected: "Beklenmeyen görüntüleme hatası",
  errorBoundaryTryAgain: "Tekrar Dene",
  errorBoundaryReload: "Pencereyi Yenile",
  skipToMain: "Ana içeriğe geç",
  workspaceAria: "Çalışma alanı",
  backendUnreachableTitle: "vdpi masaüstü arka ucuna ulaşılamıyor",
  settingsLoadErrorTitle: "vdpi ayarları yüklenemiyor",
  retryAction: "Tekrar Dene",
  configWarningTitle: "Yapılandırma uyarısı",

  // App toasts & actions
  surfaceMenuBar: "Menü çubuğu",
  surfaceTray: "Tepsi",
  trayActionCancelled: "{surface} işlemi iptal edildi.",
  trayActionFailed: "{surface} işlemi başarısız oldu.",
  actionNeedsRestart: "İşlem tamamlandı. Uygulamak için servisi yeniden başlatın.",
  protectionCancelled: "Koruma değişikliği iptal edildi.",
  protectionUpdateFailed: "Koruma durumu güncellenemedi.",
  protectionNeedsRestart:
    "Koruma güncellendi. Uygulamak için servisi yeniden başlatın.",
  protectionToggleFailed: "Koruma durumu değiştirilemedi.",
  engineSwitchCancelled: "{engine} motoruna geçiş iptal edildi.",
  engineSwitchFailed: "{engine} motoruna geçilemedi.",
  engineSwitchNeedsRestart:
    "Motor {engine} olarak değiştirildi. Uygulamak için servisi yeniden başlatın.",
  engineSwitchSuccess: "Motor {engine} olarak değiştirildi.",
  engineSwitchGenericFailed: "Koruma motoru değiştirilemedi.",
  installCancelled: "Servis kurulumu iptal edildi.",
  installFailed: "Arka plan servisi kurulamadı.",
  installNeedsRestart: "Arka plan servisi kuruldu. Uygulamak için yeniden başlatın.",
  installSuccess: "Arka plan servisi kuruldu.",
  folderKindConfig: "yapılandırma",
  folderKindLogs: "günlük",
  folderKindApp: "uygulama",
  openFolderFailed: "{kind} klasörü açılamadı.",
  refreshStatusFailed: "vdpi durumu yenilenemedi.",
  activityCopied: "Etkinlik günlüğü panoya kopyalandı.",
  activityCopyFailed: "Etkinlik günlüğü kopyalanamadı.",
  clipboardUnavailable: "Pano API'si kullanılamıyor.",
  copyCommandFailed: "Kopyalama komutu başarısız oldu.",

  // App confirm dialogs
  discardDnsTitle: "Kaydedilmemiş DNS ve Kurallar değişiklikleri silinsin mi?",
  discardSplitTitle: "Kaydedilmemiş bölünmüş tünel değişiklikleri silinsin mi?",
  discardDnsDesc:
    "DNS ve Kurallar sekmesinde kaydedilmemiş değişiklikler var. Bu sekmeden ayrılırsanız düzenlemeleriniz silinir.",
  discardSplitDesc:
    "Bölünmüş Tünel sekmesinde kaydedilmemiş değişiklikler var. Bu sekmeden ayrılırsanız düzenlemeleriniz silinir.",
  discardConfirm: "Sil ve Ayrıl",
  discardCancel: "Kal",
  switchToTunTitle: "Tam PC (TUN) moduna geçilsin mi?",
  switchToTunDesc:
    "Tam PC (TUN) moduna geçmek korumayı yeniden başlatır; sanal bağdaştırıcı başlarken etkin bağlantılar kısa süreliğine yeniden kurulur.{adminNote}",
  switchToTunAdminWindows:
    " Arka plan servisini yeniden başlatmak için Windows yönetici onayı istenebilir.",
  switchToTunAdminMac:
    " Arka plan servisini yeniden başlatmak için macOS yönetici onayı istenebilir.",
  switchToTunConfirm: "Tam PC (TUN) Moduna Geç",
};

export const tShell = createTranslator<ShellDict>({ en, tr });

const KNOWN_ACTION_MESSAGES_TR: Record<string, string> = {
  "GUI preferences saved.": "Arayüz tercihleri kaydedildi.",
  "Protection is already paused.": "Koruma zaten duraklatılmış.",
  "Protection paused.": "Koruma duraklatıldı.",
  "Protection active (TUN).": "Koruma etkin (TUN).",
  "Protection active (Proxy).": "Koruma etkin (Proxy).",
  "Protection is already active (TUN).": "Koruma zaten etkin (TUN).",
  "Protection is already active (Proxy).": "Koruma zaten etkin (Proxy).",
  "Already using TUN engine.": "Zaten TUN motoru kullanılıyor.",
  "Already using Proxy engine.": "Zaten Proxy motoru kullanılıyor.",
  "Switched engine to TUN.": "Motor TUN olarak değiştirildi.",
  "Switched engine to Proxy.": "Motor Proxy olarak değiştirildi.",
  "Background service is not installed. Install the service from Settings first.":
    "Arka plan servisi kurulu değil. Önce Ayarlar'dan servisi kurun.",
  "Background service is already installed.": "Arka plan servisi zaten kurulu.",
  "Background service installed and started.":
    "Arka plan servisi kuruldu ve başlatıldı.",
  "Background service installed.": "Arka plan servisi kuruldu.",
  "Background service is already uninstalled.":
    "Arka plan servisi zaten kaldırılmış.",
  "Background service uninstalled.": "Arka plan servisi kaldırıldı.",
  "Exiting desktop GUI.": "Masaüstü arayüzünden çıkılıyor.",
  "Preview mode: Quit GUI is only available in the native desktop app.":
    "Önizleme modu: Arayüzden Çık yalnızca yerel masaüstü uygulamasında kullanılabilir.",
};

export function localizeActionMessage(
  lang: ResolvedLanguage,
  message: string,
): string {
  if (lang !== "tr") return message;
  const exact = KNOWN_ACTION_MESSAGES_TR[message];
  if (exact) return exact;

  const previewOpen = /^Preview mode: would open (.+)$/.exec(message);
  if (previewOpen) {
    return `Önizleme modu: şu klasör açılacaktı: ${previewOpen[1]}`;
  }
  return message;
}
