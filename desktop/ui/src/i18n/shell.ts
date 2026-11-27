import { createTranslator, type ResolvedLanguage } from "./context";
import { translateDomainRuleError } from "./dns";

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
  navInstallation: "Installation",
  updateBadgeAppAvailable: "Update available ({version})",
  updateBadgeEngineUpgrade: "Engine update available ({version})",
  updateBadgeAvailable: "Update available",
  updateBadgeSetupNeeded: "Setup needed",
  updateBadgeRepairNeeded: "Repair recommended",
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
  navAnnouncement: "{view} view",
  backendUnreachableTitle: "Unable to reach vdpi desktop backend",
  settingsLoadErrorTitle: "Unable to load vdpi settings",
  retryAction: "Retry",
  configWarningTitle: "Configuration warning",
  readonlyDmgTitle: "Running from a read-only disk image",
  readonlyDmgDesc:
    "Drag vdpi Desktop.app into your Applications folder before installing or updating so macOS can register the background service reliably.",

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
  installWintunMissing:
    "wintun.dll is missing. Restore the Wintun driver before starting TUN mode.",
  installWintunInvalid:
    "wintun.dll failed SHA-256 verification (corrupted or unexpected file). Re-extract wintun.dll from the official vdpi release archive or switch to Proxy Mode.",
  upgradeCancelled: "Engine update cancelled.",
  upgradeFailed: "Failed to update background service.",
  upgradeNeedsRestart:
    "Background service updated. Restart service to apply.",
  upgradeSuccess: "Background service updated.",
  upgradeAlreadyUpToDate: "Background service is already up to date.",
  upgradeDowngradeBlocked:
    "A newer vdpi engine is already installed. Automatic downgrade is blocked.",
  upgradeVersionUnknown:
    "Could not verify the installed vdpi version. Use Repair in Installation if needed.",
  upgradeBundledMissing:
    "Bundled vdpi engine binary is missing from this installation. Re-extract the full release archive or check your antivirus quarantine.",
  repairCancelled: "Service repair cancelled.",
  repairFailed: "Failed to repair background service.",
  repairNeedsRestart:
    "Background service repaired. Restart service to apply.",
  repairSuccess: "Background service repaired.",
  uninstallCancelled: "Service uninstall cancelled.",
  uninstallFailed: "Failed to uninstall background service.",
  uninstallSuccess: "Background service uninstalled.",
  actionBusy: "Another service operation is already in progress.",
  actionShuttingDown: "The desktop app is shutting down.",
  checkUpdatesFailed: "Could not check for updates.",
  checkUpdatesUpToDate: "vdpi is up to date ({version}).",
  checkUpdatesAvailable: "Update available: {version}.",
  openReleaseFailed: "Failed to open release page.",
  folderKindConfig: "config",
  folderKindLogs: "logs",
  folderKindApp: "app",
  openFolderFailed: "Failed to open {kind} folder.",
  refreshStatusFailed: "Could not refresh vdpi status.",
  activityCopied: "Activity log copied to clipboard.",
  activityCopyFailed: "Failed to copy activity log.",
  clipboardUnavailable: "Clipboard API unavailable.",
  copyCommandFailed: "Copy command failed.",

  // Launch update prompt dialog
  updatePromptTitleApp: "Update available",
  updatePromptTitleEngine: "Engine update ready",
  updatePromptDescApp:
    "A newer vdpi release is available on GitHub. Open the release page or review details in Installation.",
  updatePromptDescEngine:
    "This desktop app includes a newer vdpi background engine ready to install.",
  updatePromptEngineSummary:
    "Updates the installed vdpi service binary to match this app without resetting your configuration.",
  updatePromptNotesHeading: "Release highlights",
  updatePromptUpdateNow: "Update Now",
  updatePromptDownloadLatest: "Download Latest",
  updatePromptUpdating: "Updating...",
  updatePromptViewInstallation: "View in Installation",
  updatePromptNotNow: "Not Now",
  updatePromptVersionAria: "Version update from {from} to {to}",

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

export type ShellStringKey = keyof typeof en;
type ShellDict = Record<ShellStringKey, string>;

const tr: ShellDict = {
  // Sidebar
  navAsideAria: "Uygulama gezinmesi",
  navPrimaryAria: "Ana gezinme",
  navOverview: "Genel Bakış",
  navSplit: "Bölünmüş Tünel",
  navDns: "DNS ve Kurallar",
  navDiagnostics: "Tanılama",
  navSettings: "Ayarlar",
  navInstallation: "Kurulum",
  updateBadgeAppAvailable: "Güncelleme mevcut ({version})",
  updateBadgeEngineUpgrade: "Motor güncellemesi mevcut ({version})",
  updateBadgeAvailable: "Güncelleme mevcut",
  updateBadgeSetupNeeded: "Kurulum gerekli",
  updateBadgeRepairNeeded: "Onarım önerilir",
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
  navAnnouncement: "{view} görünümü",
  backendUnreachableTitle: "vdpi masaüstü arka ucuna ulaşılamıyor",
  settingsLoadErrorTitle: "vdpi ayarları yüklenemiyor",
  retryAction: "Tekrar Dene",
  configWarningTitle: "Yapılandırma uyarısı",
  readonlyDmgTitle: "Salt okunur disk görüntüsünden çalışıyor",
  readonlyDmgDesc:
    "macOS'un arka plan servisini güvenilir şekilde kaydedebilmesi için kurulum veya güncellemeden önce vdpi Desktop.app uygulamasını Uygulamalar klasörüne sürükleyin.",

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
  installWintunMissing:
    "wintun.dll eksik. TUN modunu başlatmadan önce Wintun sürücüsünü geri yükleyin.",
  installWintunInvalid:
    "wintun.dll SHA-256 doğrulamasından geçemedi (bozuk veya beklenmeyen dosya). wintun.dll dosyasını resmi vdpi sürüm arşivinden yeniden çıkarın veya Proxy Moduna geçin.",
  upgradeCancelled: "Motor güncellemesi iptal edildi.",
  upgradeFailed: "Arka plan servisi güncellenemedi.",
  upgradeNeedsRestart:
    "Arka plan servisi güncellendi. Uygulamak için servisi yeniden başlatın.",
  upgradeSuccess: "Arka plan servisi güncellendi.",
  upgradeAlreadyUpToDate: "Arka plan servisi zaten güncel.",
  upgradeDowngradeBlocked:
    "Daha yeni bir vdpi motoru zaten kurulu. Otomatik sürüm düşürme engellendi.",
  upgradeVersionUnknown:
    "Kurulu vdpi sürümü doğrulanamadı. Gerekirse Kurulum sekmesinden Onar seçeneğini kullanın.",
  upgradeBundledMissing:
    "Paketli vdpi motor ikili dosyası bu kurulumda bulunamadı. Sürüm arşivini eksiksiz yeniden çıkarın veya antivirüs karantinasını kontrol edin.",
  repairCancelled: "Servis onarımı iptal edildi.",
  repairFailed: "Arka plan servisi onarılamadı.",
  repairNeedsRestart:
    "Arka plan servisi onarıldı. Uygulamak için servisi yeniden başlatın.",
  repairSuccess: "Arka plan servisi onarıldı.",
  uninstallCancelled: "Servis kaldırma işlemi iptal edildi.",
  uninstallFailed: "Arka plan servisi kaldırılamadı.",
  uninstallSuccess: "Arka plan servisi kaldırıldı.",
  actionBusy: "Başka bir servis işlemi zaten devam ediyor.",
  actionShuttingDown: "Masaüstü uygulaması kapatılıyor.",
  checkUpdatesFailed: "Güncellemeler denetlenemedi.",
  checkUpdatesUpToDate: "vdpi güncel ({version}).",
  checkUpdatesAvailable: "Güncelleme mevcut: {version}.",
  openReleaseFailed: "Sürüm sayfası açılamadı.",
  folderKindConfig: "yapılandırma",
  folderKindLogs: "günlük",
  folderKindApp: "uygulama",
  openFolderFailed: "{kind} klasörü açılamadı.",
  refreshStatusFailed: "vdpi durumu yenilenemedi.",
  activityCopied: "Etkinlik günlüğü panoya kopyalandı.",
  activityCopyFailed: "Etkinlik günlüğü kopyalanamadı.",
  clipboardUnavailable: "Pano API'si kullanılamıyor.",
  copyCommandFailed: "Kopyalama komutu başarısız oldu.",

  // Launch update prompt dialog
  updatePromptTitleApp: "Güncelleme mevcut",
  updatePromptTitleEngine: "Motor güncellemesi hazır",
  updatePromptDescApp:
    "GitHub üzerinde daha yeni bir vdpi sürümü mevcut. Sürüm sayfasını açabilir veya ayrıntıları Kurulum sekmesinde inceleyebilirsiniz.",
  updatePromptDescEngine:
    "Bu masaüstü uygulaması, kuruluma hazır daha yeni bir vdpi arka plan motoru içeriyor.",
  updatePromptEngineSummary:
    "Yapılandırmanızı sıfırlamadan kurulu vdpi servis ikili dosyasını bu uygulamayla eşleşecek şekilde günceller.",
  updatePromptNotesHeading: "Sürüm öne çıkanları",
  updatePromptUpdateNow: "Şimdi Güncelle",
  updatePromptDownloadLatest: "Son Sürümü İndir",
  updatePromptUpdating: "Güncelleniyor...",
  updatePromptViewInstallation: "Kurulumda Gör",
  updatePromptNotNow: "Şimdi Değil",
  updatePromptVersionAria: "{from} sürümünden {to} sürümüne güncelleme",

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

export const SHELL_STRINGS: {
  en: Record<ShellStringKey, string>;
  tr: Record<ShellStringKey, string>;
} = { en, tr };

export const tShell = createTranslator<ShellDict>(SHELL_STRINGS);

const KNOWN_ACTION_MESSAGES_TR: Record<string, string> = {
  "GUI preferences saved.": "Arayüz tercihleri kaydedildi.",
  "Elevation was cancelled.": "Yönetici onayı iptal edildi.",
  "Administrator authorization was cancelled. Split tunneling settings were not changed.":
    "Yönetici onayı iptal edildi. Bölünmüş tünel ayarları değiştirilmedi.",
  "Application is shutting down.": "Uygulama kapatılıyor.",
  "Service installation is already in progress.":
    "Servis kurulumu zaten devam ediyor.",
  "Service upgrade is already in progress.":
    "Servis güncellemesi zaten devam ediyor.",
  "Service repair is already in progress.":
    "Servis onarımı zaten devam ediyor.",
  "Service uninstall is already in progress.":
    "Servis kaldırma işlemi zaten devam ediyor.",
  "A protection toggle is already in progress.":
    "Koruma durumu değişikliği zaten devam ediyor.",
  "An engine switch is already in progress.":
    "Motor değişikliği zaten devam ediyor.",
  "Configuration changes are currently being applied.":
    "Yapılandırma değişiklikleri şu anda uygulanıyor.",
  "Another service action is already in progress.":
    "Başka bir servis işlemi zaten devam ediyor.",
  "Protection enabled.": "Koruma etkinleştirildi.",
  "Protection is already paused.": "Koruma zaten duraklatılmış.",
  "Protection paused.": "Koruma duraklatıldı.",
  "Protection active (TUN).": "Koruma etkin (TUN).",
  "Protection active (Proxy).": "Koruma etkin (Proxy).",
  "Protection is already active (TUN).": "Koruma zaten etkin (TUN).",
  "Protection is already active (Proxy).": "Koruma zaten etkin (Proxy).",
  "Settings saved. Restart protection to apply changes.":
    "Ayarlar kaydedildi. Değişiklikleri uygulamak için korumayı yeniden başlatın.",
  "DNS and routing rules saved.": "DNS ve yönlendirme kuralları kaydedildi.",
  "DNS and routing settings are already up to date.":
    "DNS ve yönlendirme ayarları zaten güncel.",
  "Already using TUN engine.": "Zaten TUN motoru kullanılıyor.",
  "Already using Proxy engine.": "Zaten Proxy motoru kullanılıyor.",
  "Switched engine to TUN.": "Motor TUN olarak değiştirildi.",
  "Switched engine to Proxy.": "Motor Proxy olarak değiştirildi.",
  "Background service is not installed. Install the service from Settings first.":
    "Arka plan servisi kurulu değil. Önce Kurulum sekmesinden servisi kurun.",
  "Background service is not installed. Install the service from Installation first.":
    "Arka plan servisi kurulu değil. Önce Kurulum sekmesinden servisi kurun.",
  "Background service is not installed. Install the service from Installation or Settings first.":
    "Arka plan servisi kurulu değil. Önce Kurulum veya Ayarlar sekmesinden servisi kurun.",
  "Background service is not installed. Install the service first.":
    "Arka plan servisi kurulu değil. Önce servisi kurun.",
  "Background service is already installed.": "Arka plan servisi zaten kurulu.",
  "Background service installed and started.":
    "Arka plan servisi kuruldu ve başlatıldı.",
  "Background service installed.": "Arka plan servisi kuruldu.",
  "Background service is already up to date.":
    "Arka plan servisi zaten güncel.",
  "Background service updated and started.":
    "Arka plan servisi güncellendi ve başlatıldı.",
  "Background service updated.": "Arka plan servisi güncellendi.",
  "Background service repaired and started.":
    "Arka plan servisi onarıldı ve başlatıldı.",
  "Background service repaired.": "Arka plan servisi onarıldı.",
  "A newer vdpi engine is already installed. Automatic downgrade is blocked.":
    "Daha yeni bir vdpi motoru zaten kurulu. Otomatik sürüm düşürme engellendi.",
  "Could not determine the currently installed vdpi CLI version. Use Repair to overwrite the existing installation.":
    "Kurulu vdpi CLI sürümü belirlenemedi. Mevcut kurulumun üzerine yazmak için Onar seçeneğini kullanın.",
  "Could not determine installed or bundled vdpi CLI version to perform a safe upgrade. Use Repair if the installed binary is missing or damaged.":
    "Güvenli güncelleme için kurulu veya paketli vdpi CLI sürümü belirlenemedi. Kurulu ikili dosya eksik veya hasarlıysa Onar seçeneğini kullanın.",
  "Installed engine version could not be determined. Use Repair / Reinstall instead.":
    "Kurulu motor sürümü belirlenemedi. Bunun yerine Onar / Yeniden Kur seçeneğini kullanın.",
  "Bundled vdpi engine binary was not found in the application folder.":
    "Paketli vdpi motor ikili dosyası uygulama klasöründe bulunamadı.",
  "wintun.dll is missing beside vdpi.exe. Extract all files or use Proxy mode.":
    "vdpi.exe yanında wintun.dll eksik. Tüm dosyaları çıkarın veya Proxy modunu kullanın.",
  "wintun.dll failed SHA-256 hash verification (file may be corrupted or tampered) - reinstall vdpi Desktop or replace wintun.dll from an official release.":
    "wintun.dll SHA-256 doğrulamasından geçemedi (dosya bozuk veya değiştirilmiş olabilir) - vdpi Desktop uygulamasını yeniden kurun veya wintun.dll dosyasını resmi bir sürümden değiştirin.",
  "Directory does not exist yet.": "Klasör henüz mevcut değil.",
  "Opened folder.": "Klasör açıldı.",
  "Failed to open folder in File Explorer.":
    "Klasör Dosya Gezgini'nde açılamadı.",
  "Failed to open folder in Finder.": "Klasör Finder'da açılamadı.",
  "Failed to open folder in file manager.":
    "Klasör dosya yöneticisinde açılamadı.",
  "File Explorer executable could not be found.":
    "Dosya Gezgini yürütülebilir dosyası bulunamadı.",
  "Failed to inspect target directory.": "Hedef klasör incelenemedi.",
  "Target path is not a directory.": "Hedef yol bir klasör değil.",
  "Target path is not a valid directory.": "Hedef yol geçerli bir klasör değil.",
  "Failed to create logs directory.": "Günlük klasörü oluşturulamadı.",
  "Opening directories in the OS file manager is not supported on this platform.":
    "İşletim sistemi dosya yöneticisinde klasör açma bu platformda desteklenmiyor.",
  "Background service is already uninstalled.":
    "Arka plan servisi zaten kaldırılmış.",
  "Background service uninstalled.": "Arka plan servisi kaldırıldı.",
  "Uninstalled vdpi background service and restored system proxy settings.":
    "vdpi arka plan servisi kaldırıldı ve sistem proxy ayarları geri yüklendi.",
  "Uninstalled vdpi background service. Restart protection if needed.":
    "vdpi arka plan servisi kaldırıldı. Gerekirse korumayı yeniden başlatın.",
  "Opened page in default browser.": "Sayfa varsayılan tarayıcıda açıldı.",
  "Failed to launch default web browser.":
    "Varsayılan web tarayıcısı başlatılamadı.",
  "Opening external URLs is not supported on this platform.":
    "Harici URL açma bu platformda desteklenmiyor.",
  "External URL contains invalid characters.":
    "Harici URL geçersiz karakterler içeriyor.",
  "External URL cannot be empty.": "Harici URL boş olamaz.",
  "External URL exceeds maximum allowed length.":
    "Harici URL izin verilen en fazla uzunluğu aşıyor.",
  "Refusing to open disallowed external URL.":
    "İzin verilmeyen harici URL açılmadı.",
  "Refusing to open URL outside the official vdpi GitHub repository.":
    "Resmi vdpi GitHub deposu dışındaki URL açılmadı.",
  "Refusing to open URL outside the official vdpi GitHub repository or releases.":
    "Resmi vdpi GitHub deposu veya sürümleri dışındaki URL açılmadı.",
  "External URL contains an invalid release path.":
    "Harici URL geçersiz bir sürüm yolu içeriyor.",
  "External URL contains invalid characters in release path.":
    "Harici URL sürüm yolunda geçersiz karakterler içeriyor.",
  "Only valid http:// or https:// URLs can be opened externally.":
    "Yalnızca geçerli http:// veya https:// URL'leri harici olarak açılabilir.",
  "Only http:// and https:// URLs can be opened externally.":
    "Yalnızca http:// ve https:// URL'leri harici olarak açılabilir.",
  "Could not locate application directory.": "Uygulama dizini bulunamadı.",
  "Unknown folder target. Expected 'config', 'logs', or 'app'.":
    "Bilinmeyen klasör hedefi. 'config', 'logs' veya 'app' bekleniyordu.",
  "Application names cannot contain control characters or newlines.":
    "Uygulama adları denetim karakterleri veya yeni satır içeremez.",
  "Domain entries cannot contain control characters.":
    "Alan adı girişleri denetim karakterleri içeremez.",
  "Domain entries cannot contain whitespace.":
    "Alan adı girişleri boşluk içeremez.",
  "Domain entries must not include a URL scheme (e.g. https://).":
    "Alan adı girişleri URL şeması içermemelidir (örn. https://).",
  "Domain entries must not include a URL scheme.":
    "Alan adı girişleri URL şeması içermemelidir.",
  "Domain entries cannot contain paths unless using valid CIDR notation (e.g. 203.0.113.0/24).":
    "Geçerli CIDR gösterimi (örn. 203.0.113.0/24) kullanılmadıkça alan adı girişleri yol içeremez.",
  "Exiting desktop GUI.": "Masaüstü arayüzünden çıkılıyor.",
  "Preview mode: Quit GUI is only available in the native desktop app.":
    "Önizleme modu: Arayüzden Çık yalnızca yerel masaüstü uygulamasında kullanılabilir.",
};

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

function localizeSplitSuffixTr(text: string): string {
  return text
    .replace(
      /Warning: empty Include protects no apps until at least one application is added\./g,
      "Uyarı: boş Dahil Et listesi en az bir uygulama eklenene kadar hiçbir uygulamayı korumaz.",
    )
    .replace(
      /Notice: split tunnel app list exceeded the maximum of (\d+) apps; truncated (\d+) extra apps?\./g,
      "Not: bölünmüş tünel uygulama listesi en fazla $1 uygulama sınırını aştı; $2 fazla uygulama kırpıldı.",
    )
    .replace(
      /Restart protection to apply changes\./g,
      "Değişiklikleri uygulamak için korumayı yeniden başlatın.",
    );
}

function formatFileManagerTr(target: string): string {
  switch (target.trim().toLowerCase()) {
    case "file explorer":
      return "Dosya Gezgini'nde";
    case "finder":
      return "Finder'da";
    case "file manager":
      return "dosya yöneticisinde";
    default:
      return `${target.trim()} içinde`;
  }
}

function localizeDomainReasonTr(reason: string): string {
  const trimmed = reason.trim();
  const exact = KNOWN_ACTION_MESSAGES_TR[trimmed];
  if (exact) return exact;

  const translatedRuleErr = translateDomainRuleError("tr", trimmed);
  if (translatedRuleErr && translatedRuleErr !== trimmed) {
    return translatedRuleErr;
  }

  const maxLen =
    /^Domain entry exceeds maximum length of (\d+) characters\.?$/i.exec(
      trimmed,
    );
  if (maxLen) {
    return `Alan adı girişi en fazla ${maxLen[1]} karakter uzunluğunu aşıyor.`;
  }

  const maxEntries =
    /^Domain list exceeds maximum of (\d+) entries\.?$/i.exec(trimmed);
  if (maxEntries) {
    return `Alan adı listesi en fazla ${maxEntries[1]} giriş sınırını aşıyor.`;
  }

  return trimmed;
}

export function localizeActionMessage(
  lang: ResolvedLanguage,
  message: string,
): string {
  if (lang !== "tr") return message;
  const exact = KNOWN_ACTION_MESSAGES_TR[message];
  if (exact) return exact;

  if (/wintun\.dll failed SHA-256 hash verification/i.test(message)) {
    return "wintun.dll SHA-256 doğrulamasından geçemedi (dosya bozuk veya değiştirilmiş olabilir) - vdpi Desktop uygulamasını yeniden kurun veya wintun.dll dosyasını resmi bir sürümden değiştirin.";
  }

  const openFolderExitCode =
    /^Failed to open folder in (.+?) \(exit code (-?\d+)\)\.?$/i.exec(message);
  if (openFolderExitCode) {
    return `Klasör ${formatFileManagerTr(openFolderExitCode[1])} açılamadı (çıkış kodu ${openFolderExitCode[2]}).`;
  }

  const openFolderPrefix =
    /^Failed to open folder in ([^:]+?)(?::\s*(.+))?\.?$/i.exec(message);
  if (openFolderPrefix) {
    const where = formatFileManagerTr(openFolderPrefix[1]);
    return openFolderPrefix[2]
      ? `Klasör ${where} açılamadı: ${openFolderPrefix[2]}`
      : `Klasör ${where} açılamadı.`;
  }

  const invalidBypassDomains = /^Invalid bypass domains:\s*(.+)$/i.exec(
    message,
  );
  if (invalidBypassDomains) {
    return `Geçersiz hariç tutulan alan adları: ${localizeDomainReasonTr(invalidBypassDomains[1])}`;
  }

  const invalidIncludeDomains = /^Invalid include domains:\s*(.+)$/i.exec(
    message,
  );
  if (invalidIncludeDomains) {
    return `Geçersiz dahil edilen alan adları: ${localizeDomainReasonTr(invalidIncludeDomains[1])}`;
  }

  const invalidDomainRule = /^Invalid domain rule:\s*(.+)$/i.exec(message);
  if (invalidDomainRule) {
    return `Geçersiz alan adı kuralı: ${localizeDomainReasonTr(invalidDomainRule[1])}`;
  }

  const standaloneDomainReason = localizeDomainReasonTr(message);
  if (standaloneDomainReason !== message.trim()) {
    return standaloneDomainReason;
  }

  const ipcTimeout = /^IPC command "([^"]+)" timed out after (\d+)s\.$/.exec(
    message,
  );
  if (ipcTimeout) {
    return `"${ipcTimeout[1]}" IPC komutu ${ipcTimeout[2]} sn sonra zaman aşımına uğradı.`;
  }

  const installStarted =
    /^Installed and started vdpi background service \((Proxy|TUN) mode\)\.$/.exec(
      message,
    );
  if (installStarted) {
    return `vdpi arka plan servisi kuruldu ve başlatıldı (${installStarted[1]} modu).`;
  }

  const installRestartNoDetail =
    /^Installed vdpi background service \((Proxy|TUN) mode\), but failed to restart the background service\. Restart protection to apply changes\.$/.exec(
      message,
    );
  if (installRestartNoDetail) {
    return `vdpi arka plan servisi kuruldu (${installRestartNoDetail[1]} modu), ancak arka plan servisi yeniden başlatılamadı. Değişiklikleri uygulamak için korumayı yeniden başlatın.`;
  }

  const installRestartDetail =
    /^Installed vdpi background service \((Proxy|TUN) mode\), but failed to restart the background service: (.+)$/.exec(
      message,
    );
  if (installRestartDetail) {
    return `vdpi arka plan servisi kuruldu (${installRestartDetail[1]} modu), ancak arka plan servisi yeniden başlatılamadı: ${installRestartDetail[2]}`;
  }

  const upgradeOk =
    /^Upgraded vdpi background service(?: to (v?[^\s.]+))?\.$/.exec(message);
  if (upgradeOk) {
    return upgradeOk[1]
      ? `vdpi arka plan servisi ${upgradeOk[1]} sürümüne güncellendi.`
      : "vdpi arka plan servisi güncellendi.";
  }

  const upgradeRestartNoDetail =
    /^Upgraded vdpi background service(?: to (v?[^\s,]+))?, but failed to restart the background service\. Restart protection to apply changes\.$/.exec(
      message,
    );
  if (upgradeRestartNoDetail) {
    return upgradeRestartNoDetail[1]
      ? `vdpi arka plan servisi ${upgradeRestartNoDetail[1]} sürümüne güncellendi, ancak arka plan servisi yeniden başlatılamadı. Değişiklikleri uygulamak için korumayı yeniden başlatın.`
      : "vdpi arka plan servisi güncellendi, ancak arka plan servisi yeniden başlatılamadı. Değişiklikleri uygulamak için korumayı yeniden başlatın.";
  }

  const upgradeRestartDetail =
    /^Upgraded vdpi background service(?: to (v?[^\s,]+))?, but failed to restart the background service: (.+)$/.exec(
      message,
    );
  if (upgradeRestartDetail) {
    return upgradeRestartDetail[1]
      ? `vdpi arka plan servisi ${upgradeRestartDetail[1]} sürümüne güncellendi, ancak arka plan servisi yeniden başlatılamadı: ${upgradeRestartDetail[2]}`
      : `vdpi arka plan servisi güncellendi, ancak arka plan servisi yeniden başlatılamadı: ${upgradeRestartDetail[2]}`;
  }

  const alreadyUpToDateVer =
    /^(?:Background service|Engine) is already up to date \((v?[^)]+)\)\.$/.exec(
      message,
    );
  if (alreadyUpToDateVer) {
    return `Arka plan servisi zaten güncel (${alreadyUpToDateVer[1]}).`;
  }

  const engineUpdatedTo = /^Engine updated to (v?[^\s.]+)\.$/.exec(message);
  if (engineUpdatedTo) {
    return `Motor ${engineUpdatedTo[1]} sürümüne güncellendi.`;
  }

  const downgradeRefused =
    /^Refusing to downgrade installed vdpi (v?[^\s]+) to older bundled (v?[^\s]+)(?: during repair)?\..*$/.exec(
      message,
    );
  if (downgradeRefused) {
    return `Kurulu vdpi ${downgradeRefused[1]} sürümünü daha eski paketli ${downgradeRefused[2]} sürümüne düşürme engellendi.`;
  }

  const downgradeBlockedMock =
    /^Installed engine (v?[^\s]+) is newer than bundled (v?[^\s]+)\. Downgrade blocked\.$/.exec(
      message,
    );
  if (downgradeBlockedMock) {
    return `Kurulu motor (${downgradeBlockedMock[1]}) paketli sürümden (${downgradeBlockedMock[2]}) daha yeni. Sürüm düşürme engellendi.`;
  }

  const repairRestarted =
    /^Repaired and restarted vdpi background service \((Proxy|TUN) mode\)\.$/.exec(
      message,
    );
  if (repairRestarted) {
    return `vdpi arka plan servisi onarıldı ve yeniden başlatıldı (${repairRestarted[1]} modu).`;
  }

  const repairRestartNoDetail =
    /^Repaired vdpi background service \((Proxy|TUN) mode\), but failed to restart the background service\. Restart protection to apply changes\.$/.exec(
      message,
    );
  if (repairRestartNoDetail) {
    return `vdpi arka plan servisi onarıldı (${repairRestartNoDetail[1]} modu), ancak arka plan servisi yeniden başlatılamadı. Değişiklikleri uygulamak için korumayı yeniden başlatın.`;
  }

  const repairRestartDetail =
    /^Repaired vdpi background service \((Proxy|TUN) mode\), but failed to restart the background service: (.+)$/.exec(
      message,
    );
  if (repairRestartDetail) {
    return `vdpi arka plan servisi onarıldı (${repairRestartDetail[1]} modu), ancak arka plan servisi yeniden başlatılamadı: ${repairRestartDetail[2]}`;
  }

  const repairMockVer = /^Background service repaired \((v?[^)]+)\)\.$/.exec(
    message,
  );
  if (repairMockVer) {
    return `Arka plan servisi onarıldı (${repairMockVer[1]}).`;
  }

  const switchRestarted =
    /^Switched engine to (Proxy|TUN) mode and restarted background service\.$/.exec(
      message,
    );
  if (switchRestarted) {
    return `Motor ${switchRestarted[1]} moduna geçirildi ve arka plan servisi yeniden başlatıldı.`;
  }

  const switchDeferred =
    /^Switched engine to (Proxy|TUN) mode\. It will take effect when protection is enabled\.$/.exec(
      message,
    );
  if (switchDeferred) {
    return `Motor ${switchDeferred[1]} moduna geçirildi. Koruma etkinleştirildiğinde geçerli olacak.`;
  }

  const switchRestartNoDetail =
    /^Switched engine to (Proxy|TUN) mode, but failed to restart the background service\. Restart protection to apply changes\.$/.exec(
      message,
    );
  if (switchRestartNoDetail) {
    return `Motor ${switchRestartNoDetail[1]} moduna geçirildi, ancak arka plan servisi yeniden başlatılamadı. Değişiklikleri uygulamak için korumayı yeniden başlatın.`;
  }

  const switchRestartDetail =
    /^Switched engine to (Proxy|TUN) mode, but failed to restart the background service: (.+)$/.exec(
      message,
    );
  if (switchRestartDetail) {
    return `Motor ${switchRestartDetail[1]} moduna geçirildi, ancak arka plan servisi yeniden başlatılamadı: ${switchRestartDetail[2]}`;
  }

  const savedModeNotInstalled =
    /^Saved (Proxy|TUN) mode\. Background service is not installed yet; install the service to activate it\.$/.exec(
      message,
    );
  if (savedModeNotInstalled) {
    return `${savedModeNotInstalled[1]} modu kaydedildi. Arka plan servisi henüz kurulu değil; etkinleştirmek için servisi kurun.`;
  }

  const dnsSavedRestarted =
    /^Saved DNS \((.+?)\) and routing rules, and restarted background service\.$/.exec(
      message,
    );
  if (dnsSavedRestarted) {
    return `DNS (${dnsSavedRestarted[1]}) ve yönlendirme kuralları kaydedildi, arka plan servisi yeniden başlatıldı.`;
  }

  const dnsSavedRestartNeeded =
    /^Saved DNS \((.+?)\) and routing rules\. Restart protection to apply changes\.$/.exec(
      message,
    );
  if (dnsSavedRestartNeeded) {
    return `DNS (${dnsSavedRestartNeeded[1]}) ve yönlendirme kuralları kaydedildi. Değişiklikleri uygulamak için korumayı yeniden başlatın.`;
  }

  const dnsSavedPlain = /^Saved DNS \((.+?)\) and routing rules\.$/.exec(
    message,
  );
  if (dnsSavedPlain) {
    return `DNS (${dnsSavedPlain[1]}) ve yönlendirme kuralları kaydedildi.`;
  }

  const dnsSavedRestartFailNoDetail =
    /^Saved DNS \((.+?)\) and routing rules, but failed to restart the background service\. Restart protection to apply changes\.$/.exec(
      message,
    );
  if (dnsSavedRestartFailNoDetail) {
    return `DNS (${dnsSavedRestartFailNoDetail[1]}) ve yönlendirme kuralları kaydedildi, ancak arka plan servisi yeniden başlatılamadı. Değişiklikleri uygulamak için korumayı yeniden başlatın.`;
  }

  const dnsSavedRestartFailDetail =
    /^Saved DNS \((.+?)\) and routing rules, but failed to restart the background service: (.+)$/.exec(
      message,
    );
  if (dnsSavedRestartFailDetail) {
    return `DNS (${dnsSavedRestartFailDetail[1]}) ve yönlendirme kuralları kaydedildi, ancak arka plan servisi yeniden başlatılamadı: ${dnsSavedRestartFailDetail[2]}`;
  }

  const splitSaved =
    /^Split tunneling saved: (All apps|(?:Exclude|Include) \(\d+ apps?\))(?:\s*\((service restarted|applied live)\))?(.*)$/.exec(
      message,
    );
  if (splitSaved) {
    const localizedSummary = localizeSplitSummaryTr(splitSaved[1]);
    const liveNote =
      splitSaved[2] === "service restarted"
        ? " (servis yeniden başlatıldı)"
        : splitSaved[2] === "applied live"
          ? " (canlı uygulandı)"
          : "";
    const tail = splitSaved[3] ? localizeSplitSuffixTr(splitSaved[3]) : "";
    return `Bölünmüş tünel kaydedildi: ${localizedSummary}${liveNote}${tail}`;
  }

  const traySyncErr =
    /^GUI preferences saved, but failed to synchronize (menu bar|system tray): (.+)$/.exec(
      message,
    );
  if (traySyncErr) {
    const surface =
      traySyncErr[1] === "menu bar" ? "menü çubuğu" : "sistem tepsisi";
    return `Arayüz tercihleri kaydedildi, ancak ${surface} eşitlenemedi: ${traySyncErr[2]}`;
  }

  const wintunMissingFallback =
    /^wintun\.dll is missing (?:-|\u2014) reinstall vdpi Desktop, extract all files from the zip, or check Windows Defender quarantine\.$/.exec(
      message,
    );
  if (wintunMissingFallback) {
    return "wintun.dll eksik - vdpi Desktop uygulamasını yeniden kurun, zip arşivindeki tüm dosyaları çıkarın veya Windows Defender karantinasını kontrol edin.";
  }

  const failedPrefixPatterns: ReadonlyArray<
    readonly [RegExp, (match: RegExpExecArray) => string]
  > = [
    [
      /^Failed to enable protection: (.+)$/,
      (m) => `Koruma etkinleştirilemedi: ${m[1]}`,
    ],
    [
      /^Failed to pause protection: (.+)$/,
      (m) => `Koruma duraklatılamadı: ${m[1]}`,
    ],
    [
      /^Failed to toggle protection: (.+)$/,
      (m) => `Koruma durumu değiştirilemedi: ${m[1]}`,
    ],
    [
      /^Failed to switch engine to (Proxy|TUN) mode: (.+)$/,
      (m) => `Motor ${m[1]} moduna geçirilemedi: ${m[2]}`,
    ],
    [/^Failed to switch engine: (.+)$/, (m) => `Motor değiştirilemedi: ${m[1]}`],
    [
      /^Failed to install background service: (.+)$/,
      (m) => `Arka plan servisi kurulamadı: ${m[1]}`,
    ],
    [
      /^Failed to upgrade background service: (.+)$/,
      (m) => `Arka plan servisi güncellenemedi: ${m[1]}`,
    ],
    [
      /^Failed to repair background service: (.+)$/,
      (m) => `Arka plan servisi onarılamadı: ${m[1]}`,
    ],
    [
      /^Failed to uninstall background service: (.+)$/,
      (m) => `Arka plan servisi kaldırılamadı: ${m[1]}`,
    ],
    [
      /^Failed to save DNS and routing (?:settings|rules): (.+)$/,
      (m) => `DNS ve yönlendirme kuralları kaydedilemedi: ${m[1]}`,
    ],
    [
      /^Failed to apply split tunneling settings: (.+)$/,
      (m) => `Bölünmüş tünel ayarları uygulanamadı: ${m[1]}`,
    ],
    [
      /^Failed to save split(?: tunneling settings|-tunnel configuration): (.+)$/,
      (m) => `Bölünmüş tünel ayarları kaydedilemedi: ${m[1]}`,
    ],
    [
      /^Failed to save GUI preferences: (.+)$/,
      (m) => `Arayüz tercihleri kaydedilemedi: ${m[1]}`,
    ],
    [
      /^Failed to open application folder: (.+)$/,
      (m) => `Uygulama klasörü açılamadı: ${m[1]}`,
    ],
    [
      /^Failed to open external URL: (.+)$/,
      (m) => `Harici URL açılamadı: ${m[1]}`,
    ],
    [
      /^Failed to launch default web browser \(exit code (-?\d+)\)\.$/,
      (m) => `Varsayılan web tarayıcısı başlatılamadı (çıkış kodu ${m[1]}).`,
    ],
  ];

  for (const [pattern, formatter] of failedPrefixPatterns) {
    const match = pattern.exec(message);
    if (match) {
      return formatter(match);
    }
  }

  const previewOpen = /^Preview mode: would open (.+)$/.exec(message);
  if (previewOpen) {
    return `Önizleme modu: şu klasör açılacaktı: ${previewOpen[1]}`;
  }
  const previewExternal = /^Preview mode: opened (.+)$/.exec(message);
  if (previewExternal) {
    return `Önizleme modu: ${previewExternal[1]} açıldı`;
  }
  return message.replace(/vdpi'ı/g, "vdpi'yi").replace(/vdpi'ın/g, "vdpi'nin");
}
