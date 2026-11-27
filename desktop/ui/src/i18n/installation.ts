import { createTranslator } from "./context";

const en = {
  // Header
  title: "Installation",
  subtitle:
    "Install, update, repair, or remove the background vdpi engine.",

  // Loading
  loadingStatus: "Checking installation status...",

  // App Release Update Card
  releaseCardTitle: "New Desktop Release Available",
  releaseCardBadge: "Update",
  releaseVersionSummary: "{current} -> {latest}",
  releaseNotesLabel: "What's new",
  btnDownloadRelease: "Download Latest Release",
  btnCheckAgain: "Check Again",
  btnChecking: "Checking...",

  // macOS Read-only DMG Notice
  dmgNoticeTitle: "Running from a read-only disk image",
  dmgNoticeDesc:
    "Drag vdpi Desktop.app into your Applications folder before installing or updating so macOS can register the background service reliably.",

  // Bundled binary missing warning
  bundledMissingTitle: "Bundled engine binary not found",
  bundledMissingDesc:
    "The vdpi engine executable is missing from the application folder. Re-extract the full release archive or check your antivirus quarantine.",

  // First-time setup card (not_installed)
  setupCardTitle: "Set Up Protection Engine",
  setupCardSubtitle:
    "Choose how vdpi routes traffic on this device. You can switch modes at any time.",
  statusNotInstalled: "Not Installed",
  engineGroupAria: "Engine mode",

  engineProxyTitle: "Proxy Mode",
  engineProxyBadge: "Recommended",
  engineProxyDesc:
    "Local HTTP/SOCKS5 proxy with zero network driver changes. Lightweight and ready immediately.",

  engineTunTitle: "TUN Mode",
  engineTunBadge: "System-wide",
  engineTunDesc:
    "Virtual adapter that protects all apps, games, and voice clients with per-app split tunneling.",

  // Wintun missing strip
  wintunMissingTitle: "wintun.dll is required for TUN Mode",
  wintunMissingDesc:
    "Keep wintun.dll next to vdpi.exe in the application folder, or select Proxy Mode instead.",
  btnRecheckWintun: "Re-check",
  btnRechecking: "Checking...",

  // Platform-accurate elevation notes
  elevationWindows:
    "Windows will show an administrator (UAC) prompt to register the background service.",
  elevationMacTun:
    "macOS will ask for your administrator password to install the system TUN service.",
  elevationLinuxTun:
    "Linux will show a Polkit authentication prompt to install the system TUN service.",
  elevationUnixProxy:
    "No administrator password required for Proxy Mode - installs as a user background service.",

  // Setup primary CTA & progress
  btnInstallAndProtect: "Install & Protect",
  btnInstalling: "Installing...",
  progressInstalling: "Installing vdpi engine and starting protection...",
  progressUpgrading:
    "Updating vdpi engine while preserving your configuration...",
  progressRepairing: "Repairing and re-registering the background service...",
  progressUninstalling:
    "Stopping protection and removing the background service...",

  // Collapsible "What gets installed" details
  detailsToggleLabel: "What gets installed",
  detailsItemBinaryWin:
    "Copies the bundled vdpi.exe engine binary into the service directory.",
  detailsItemBinaryUnix:
    "Installs the bundled vdpi engine binary for the background service.",
  detailsItemServiceWin:
    "Registers a Windows background service so protection starts reliably.",
  detailsItemServiceMac:
    "Registers a macOS LaunchDaemon / LaunchAgent for background protection.",
  detailsItemServiceLinux:
    "Registers a systemd background service for automatic protection.",
  detailsItemConfig:
    "Writes config.toml for DNS, split tunnel, and engine settings (never touches browser profiles).",
  detailsItemUninstall:
    "Can be uninstalled cleanly at any time from this screen.",

  // Error recovery banner
  errorTitleCancelled: "Installation cancelled",
  errorTitleWintun: "TUN driver unavailable",
  errorTitleAntivirus: "Blocked by security software",
  errorTitleGeneric: "Operation failed",
  errorHintCancelled:
    "Approve the system elevation prompt to finish setting up vdpi.",
  errorHintWintun:
    "wintun.dll could not be loaded. Switch to Proxy Mode or inspect the application folder.",
  errorHintAntivirus:
    "Security software may have quarantined vdpi.exe or wintun.dll. Allow the app folder and retry.",
  btnTryProxyInstead: "Try Proxy Mode Instead",
  btnRetry: "Retry",
  btnOpenAppFolder: "Open App Folder",
  btnOpenDiagnostics: "Open Diagnostics",
  btnDismissError: "Dismiss error",

  // Installed engine management card
  engineCardTitle: "Engine & Background Service",
  badgeRunning: "Running",
  badgeStopped: "Stopped",
  badgeUpgradeAvailable: "Update Ready",
  badgeUpToDate: "Up to Date",
  badgeNewerInstalled: "Newer Installed",
  badgeRepairNeeded: "Repair Needed",

  // Bundled engine upgrade banner
  upgradeBannerTitle: "Bundled engine {version} is ready",
  upgradeBannerDesc:
    "Update the installed engine from {installed} to {bundled}. Your DNS, split tunnel, and domain rules are preserved.",
  btnUpdateEngine: "Update Engine to {version}",
  btnUpdatingEngine: "Updating...",

  // Live version stale banner
  liveStaleTitle: "Service restart recommended",
  liveStaleDesc:
    "Engine on disk ({installed}) differs from the running process ({live}). Repair or restart protection to load the updated binary.",

  // Repair needed banner
  repairNeededTitle: "Service installation needs repair",
  repairNeededDesc:
    "The background service registration or binary looks incomplete. Run Repair / Reinstall to restore vdpi without losing your config.",

  // Newer installed notice
  newerInstalledTitle: "Newer engine version detected",
  newerInstalledDesc:
    "Installed engine {installed} is newer than bundled {bundled}. Repair / Reinstall is disabled so vdpi never downgrades your engine.",

  // Status grid
  metaInstalledEngine: "Installed Engine",
  metaBundledEngine: "Bundled Engine",
  metaEngineMode: "Engine Mode",
  metaServiceState: "Service State",
  metaConfigPath: "Config File",
  valueUnknown: "Unknown",
  valueUnavailable: "Unavailable",
  engineLabelTun: "TUN (System-wide)",
  engineLabelProxy: "Proxy (Local)",
  switchEngineGroupAria: "Switch engine mode",
  switchEngineProxy: "Proxy",
  switchEngineTun: "TUN",
  switchEngineWintunMissing: "Place wintun.dll next to vdpi.exe to enable TUN mode",
  serviceLabelRunning: "Running",
  serviceLabelStopped: "Stopped",
  serviceLabelNotInstalled: "Not Installed",

  // Management actions
  btnRepairReinstall: "Repair / Reinstall",
  btnRepairing: "Repairing...",
  btnCheckUpdates: "Check for Updates",
  btnUninstallService: "Uninstall Service",
  btnUninstalling: "Uninstalling...",
  repairDisabledNewerHint:
    "Disabled because a newer engine version is already installed.",
  repairDisabledBundleHint:
    "Disabled because the bundled engine binary is missing.",

  // Paths & Local Data card
  pathsCardTitle: "Paths & Local Data",
  pathConfigLabel: "Configuration",
  pathLogsLabel: "Logs",
  btnOpenFolder: "Open Folder",
  btnAppFolder: "App Folder",

  // Confirm dialogs
  repairDialogTitle: "Repair / Reinstall background service?",
  repairDialogDesc:
    "This re-copies bundled engine {version} and re-registers the background service. Active connections may reconnect briefly while your configuration stays intact.",
  repairDialogDescNoVersion:
    "This re-copies the bundled engine and re-registers the background service. Active connections may reconnect briefly while your configuration stays intact.",
  repairDialogConfirm: "Repair / Reinstall",

  uninstallDialogTitle: "Uninstall vdpi service?",
  uninstallDialogDesc:
    "This stops protection and removes the background vdpi service. Your config.toml and desktop preferences remain on disk.",
  uninstallDialogConfirm: "Uninstall Service",
  cancel: "Cancel",
} as const;

export type InstallationStringKey = keyof typeof en;
type InstallationDict = Record<InstallationStringKey, string>;

const tr: InstallationDict = {
  // Header
  title: "Kurulum",
  subtitle:
    "Arka plan vdpi motorunu kurun, güncelleyin, onarın veya kaldırın.",

  // Loading
  loadingStatus: "Kurulum durumu denetleniyor...",

  // App Release Update Card
  releaseCardTitle: "Yeni Masaüstü Sürümü Mevcut",
  releaseCardBadge: "Güncelleme",
  releaseVersionSummary: "{current} -> {latest}",
  releaseNotesLabel: "Yenilikler",
  btnDownloadRelease: "Son Sürümü İndir",
  btnCheckAgain: "Tekrar Kontrol Et",
  btnChecking: "Kontrol ediliyor...",

  // macOS Read-only DMG Notice
  dmgNoticeTitle: "Salt okunur disk görüntüsünden çalışıyor",
  dmgNoticeDesc:
    "macOS'un arka plan servisini güvenilir şekilde kaydedebilmesi için kurulum veya güncellemeden önce vdpi Desktop.app uygulamasını Uygulamalar klasörüne sürükleyin.",

  // Bundled binary missing warning
  bundledMissingTitle: "Paketli motor ikili dosyası bulunamadı",
  bundledMissingDesc:
    "vdpi motor dosyası uygulama klasöründe eksik. Sürüm arşivini eksiksiz çıkarın veya antivirüs karantinasını kontrol edin.",

  // First-time setup card (not_installed)
  setupCardTitle: "Koruma Motorunu Kur",
  setupCardSubtitle:
    "vdpi'nin bu cihazda trafiği nasıl yönlendireceğini seçin. Modu istediğiniz zaman değiştirebilirsiniz.",
  statusNotInstalled: "Kurulu Değil",
  engineGroupAria: "Motor modu",

  engineProxyTitle: "Proxy Modu",
  engineProxyBadge: "Önerilen",
  engineProxyDesc:
    "Ağ sürücüsü değişikliği gerektirmeyen yerel HTTP/SOCKS5 proxy. Hafif ve anında kullanıma hazır.",

  engineTunTitle: "TUN Modu",
  engineTunBadge: "Tüm sistem",
  engineTunDesc:
    "Uygulama bazlı bölünmüş tünelle tüm uygulamaları, oyunları ve sesli sohbetleri koruyan sanal bağdaştırıcı.",

  // Wintun missing strip
  wintunMissingTitle: "TUN Modu için wintun.dll gerekli",
  wintunMissingDesc:
    "wintun.dll dosyasını uygulama klasöründe vdpi.exe yanında tutun veya bunun yerine Proxy Modunu seçin.",
  btnRecheckWintun: "Yeniden Denetle",
  btnRechecking: "Denetleniyor...",

  // Platform-accurate elevation notes
  elevationWindows:
    "Arka plan servisini kaydetmek için Windows yönetici (UAC) onayı isteyecektir.",
  elevationMacTun:
    "Sistem TUN servisini kurmak için macOS yönetici parolanızı isteyecektir.",
  elevationLinuxTun:
    "Sistem TUN servisini kurmak için Linux Polkit kimlik doğrulama penceresi açacaktır.",
  elevationUnixProxy:
    "Proxy Modu için yönetici parolası gerekmez - kullanıcı arka plan servisi olarak kurulur.",

  // Setup primary CTA & progress
  btnInstallAndProtect: "Kur ve Koru",
  btnInstalling: "Kuruluyor...",
  progressInstalling: "vdpi motoru kuruluyor ve koruma başlatılıyor...",
  progressUpgrading:
    "Yapılandırmanız korunarak vdpi motoru güncelleniyor...",
  progressRepairing: "Arka plan servisi onarılıyor ve yeniden kaydediliyor...",
  progressUninstalling:
    "Koruma durduruluyor ve arka plan servisi kaldırılıyor...",

  // Collapsible "What gets installed" details
  detailsToggleLabel: "Neler kurulur",
  detailsItemBinaryWin:
    "Paketli vdpi.exe motor dosyasını servis dizinine kopyalar.",
  detailsItemBinaryUnix:
    "Arka plan servisi için paketli vdpi motor dosyasını kurar.",
  detailsItemServiceWin:
    "Korumanın güvenilir başlaması için bir Windows arka plan servisi kaydeder.",
  detailsItemServiceMac:
    "Arka plan koruması için bir macOS LaunchDaemon / LaunchAgent kaydeder.",
  detailsItemServiceLinux:
    "Otomatik koruma için bir systemd arka plan servisi kaydeder.",
  detailsItemConfig:
    "DNS, bölünmüş tünel ve motor ayarları için config.toml oluşturur (tarayıcı profillerine dokunmaz).",
  detailsItemUninstall:
    "Bu ekrandan istediğiniz zaman temiz şekilde kaldırılabilir.",

  // Error recovery banner
  errorTitleCancelled: "Kurulum iptal edildi",
  errorTitleWintun: "TUN sürücüsü kullanılamıyor",
  errorTitleAntivirus: "Güvenlik yazılımı tarafından engellendi",
  errorTitleGeneric: "İşlem başarısız oldu",
  errorHintCancelled:
    "vdpi'yi kurmayı tamamlamak için sistem yönetici onayını kabul edin.",
  errorHintWintun:
    "wintun.dll yüklenemedi. Proxy Moduna geçin veya uygulama klasörünü kontrol edin.",
  errorHintAntivirus:
    "Güvenlik yazılımı vdpi.exe veya wintun.dll dosyasını karantinaya almış olabilir. Uygulama klasörüne izin verip tekrar deneyin.",
  btnTryProxyInstead: "Proxy Modunu Dene",
  btnRetry: "Tekrar Dene",
  btnOpenAppFolder: "Uygulama Klasörü",
  btnOpenDiagnostics: "Tanılamayı Aç",
  btnDismissError: "Hatayı kapat",

  // Installed engine management card
  engineCardTitle: "Motor ve Arka Plan Servisi",
  badgeRunning: "Çalışıyor",
  badgeStopped: "Durduruldu",
  badgeUpgradeAvailable: "Güncelleme Hazır",
  badgeUpToDate: "Güncel",
  badgeNewerInstalled: "Daha Yeni Kurulu",
  badgeRepairNeeded: "Onarım Gerekli",

  // Bundled engine upgrade banner
  upgradeBannerTitle: "Paketli {version} motoru hazır",
  upgradeBannerDesc:
    "Kurulu motoru {installed} sürümünden {bundled} sürümüne güncelleyin. DNS, bölünmüş tünel ve alan adı kurallarınız korunur.",
  btnUpdateEngine: "Motoru {version} Sürümüne Güncelle",
  btnUpdatingEngine: "Güncelleniyor...",

  // Live version stale banner
  liveStaleTitle: "Servisi yeniden başlatın",
  liveStaleDesc:
    "Diskteki motor ({installed}) çalışan süreçten ({live}) farklı. Güncel dosyayı yüklemek için servisi onarın veya yeniden başlatın.",

  // Repair needed banner
  repairNeededTitle: "Servis kurulumunun onarılması gerekiyor",
  repairNeededDesc:
    "Arka plan servis kaydı veya ikili dosya eksik görünüyor. Yapılandırmanızı kaybetmeden vdpi'yi geri yüklemek için Onar / Yeniden Kur çalıştırın.",

  // Newer installed notice
  newerInstalledTitle: "Daha yeni motor sürümü algılandı",
  newerInstalledDesc:
    "Kurulu {installed} motoru paketli {bundled} sürümünden daha yeni. vdpi'yi yanlışlıkla eski sürüme düşürmemek için Onar / Yeniden Kur devre dışı bırakıldı.",

  // Status grid
  metaInstalledEngine: "Kurulu Motor",
  metaBundledEngine: "Paketli Motor",
  metaEngineMode: "Motor Modu",
  metaServiceState: "Servis Durumu",
  metaConfigPath: "Yapılandırma",
  valueUnknown: "Bilinmiyor",
  valueUnavailable: "Yok",
  engineLabelTun: "TUN (Tüm sistem)",
  engineLabelProxy: "Proxy (Yerel)",
  switchEngineGroupAria: "Motor modunu değiştir",
  switchEngineProxy: "Proxy",
  switchEngineTun: "TUN",
  switchEngineWintunMissing: "TUN modunu etkinleştirmek için wintun.dll dosyasını vdpi.exe yanına koyun",
  serviceLabelRunning: "Çalışıyor",
  serviceLabelStopped: "Durduruldu",
  serviceLabelNotInstalled: "Kurulu Değil",

  // Management actions
  btnRepairReinstall: "Onar / Yeniden Kur",
  btnRepairing: "Onarılıyor...",
  btnCheckUpdates: "Güncelleme Denetle",
  btnUninstallService: "Servisi Kaldır",
  btnUninstalling: "Kaldırılıyor...",
  repairDisabledNewerHint:
    "Daha yeni bir motor sürümü zaten kurulu olduğu için devre dışı.",
  repairDisabledBundleHint:
    "Paketli motor ikili dosyası eksik olduğu için devre dışı.",

  // Paths & Local Data card
  pathsCardTitle: "Yollar ve Yerel Veriler",
  pathConfigLabel: "Yapılandırma",
  pathLogsLabel: "Günlükler",
  btnOpenFolder: "Klasörü Aç",
  btnAppFolder: "Uygulama Klasörü",

  // Confirm dialogs
  repairDialogTitle: "Arka plan servisi onarılsın mı?",
  repairDialogDesc:
    "Bu işlem paketli {version} motorunu yeniden kopyalar ve arka plan servisini tekrar kaydeder. Etkin bağlantılar kısa süreliğine yeniden kurulabilir; yapılandırmanız korunur.",
  repairDialogDescNoVersion:
    "Bu işlem paketli motoru yeniden kopyalar ve arka plan servisini tekrar kaydeder. Etkin bağlantılar kısa süreliğine yeniden kurulabilir; yapılandırmanız korunur.",
  repairDialogConfirm: "Onar / Yeniden Kur",

  uninstallDialogTitle: "vdpi servisi kaldırılsın mı?",
  uninstallDialogDesc:
    "Bu işlem korumayı durdurur ve vdpi'yi çalıştıran arka plan servisini kaldırır. config.toml ve masaüstü tercihleriniz diskte kalır.",
  uninstallDialogConfirm: "Servisi Kaldır",
  cancel: "İptal",
};

export const INSTALLATION_STRINGS: {
  en: Record<InstallationStringKey, string>;
  tr: Record<InstallationStringKey, string>;
} = { en, tr };

export const tInstallation = createTranslator(INSTALLATION_STRINGS);
