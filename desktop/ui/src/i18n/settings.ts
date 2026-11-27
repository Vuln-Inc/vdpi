import { createTranslator } from "./context";

const en = {
  // Header
  title: "Settings",
  subtitleMac:
    "Control menu bar presence, background service installation, appearance, and updates.",
  subtitleDefault:
    "Control tray presence, background service installation, appearance, and updates.",

  // Window & Tray / Menu Bar card
  trayHeadingMac: "Window & Menu Bar",
  trayHeadingDefault: "Window & System Tray",
  trayBadgeUnavailable: "Tray unavailable",
  trayBadgeMenuBarActive: "Menu bar active",
  trayBadgeNoMenuBarIcon: "No menu bar icon",
  trayBadgeActive: "Tray active",
  trayBadgeNoIcon: "No tray icon",
  linuxTrayNotice:
    "System tray support was not detected in this Linux desktop environment (StatusNotifier / AppIndicator required). Tray options may not display an icon.",
  keepInTrayLabelMac: "Keep in menu bar when closed",
  keepInTrayLabelDefault: "Keep in system tray when closed",
  keepInTrayDescOnMac:
    "Closing the window hides it to the menu bar with a live status dot and quick menu.",
  keepInTrayDescOnDefault:
    "Closing the window hides it to the system tray with a live status dot and quick menu.",
  keepInTrayDescOffMac:
    "Closing the window completely exits the GUI app with zero Dock or menu bar icon.",
  keepInTrayDescOffDefault:
    "Closing the window completely exits the GUI app with zero taskbar or tray icon.",
  minimizeToTrayLabelMac: "Minimize to menu bar",
  minimizeToTrayLabelDefault: "Minimize to system tray",
  minimizeToTrayDescMac:
    "Minimizing hides the window to the menu bar and automatically enables menu bar presence.",
  minimizeToTrayDescDefault:
    "Minimizing hides the window to the system tray and automatically enables tray presence.",
  startMinimizedLabelMac: "Start minimized to menu bar",
  startMinimizedLabelDefault: "Start minimized to tray",
  startMinimizedDescMac:
    "Launch the GUI hidden in the menu bar instead of opening the main window.",
  startMinimizedDescDefault:
    "Launch the GUI hidden in the system tray instead of opening the main window.",
  showTaskbarLabelMac: "Show Dock icon when minimized",
  showTaskbarLabelDefault: "Show taskbar icon when minimized",
  showTaskbarDescMac:
    "Keep the app icon visible in the Dock while minimized to the menu bar.",
  showTaskbarDescDefault:
    "Keep the window button visible in the taskbar while minimized to the system tray.",
  trayFooterNote:
    "Closing or quitting the GUI does not stop the background vdpi service if installed.",

  // Background Service card
  serviceHeading: "Background Service",
  serviceStateRunning: "Running",
  serviceStateStopped: "Stopped",
  serviceStateNotInstalled: "Not Installed",
  serviceStateChecking: "Checking...",
  serviceRowLabel: "vdpi system service",
  serviceBinaryPrefix: "Binary:",
  serviceVersionNotInstalled: "Not installed",
  serviceVersionUnknown: "Unknown",
  btnOpenInstallation: "Open Installation",
  btnUpdateEngine: "Update Engine",
  btnUpdatingEngine: "Updating...",
  btnInstalling: "Installing...",
  btnInstallService: "Install Background Service",
  btnUninstalling: "Uninstalling...",
  btnUninstallService: "Uninstall Service",
  serviceWintunMissingNote:
    "wintun.dll is required for Full-PC (TUN) mode on Windows. Add wintun.dll or switch to Proxy mode in Installation.",

  // Appearance card
  appearanceHeading: "Appearance",
  themeLabel: "Theme",
  themeDesc:
    "Match your operating system theme or lock to dark or light mode.",
  themeSystem: "System",
  themeDark: "Dark",
  themeLight: "Light",
  languageLabel: "Language",
  languageDesc:
    "Match your operating system language or choose English or Turkish.",
  languageSystem: "System",
  languageEn: "English",
  languageTr: "Türkçe",

  // Updates & Local Data card
  updatesHeading: "Updates & Local Data",
  desktopAppLabel: "Desktop application",
  currentVersionPrefix: "Current version",
  btnCheckingUpdates: "Checking...",
  btnCheckUpdates: "Check for Updates",
  updateAvailablePrefix: "Update available:",
  upToDate: "Up to date",
  viewRelease: "View release",
  installedPrefix: "Installed",
  latestPrefix: "latest",
  runningLatestBefore: "You are running the latest version (",
  runningLatestAfter: ").",
  updateCheckFailed: "Update check failed",
  configFolderLabel: "Configuration folder",
  configFolderDescUnix:
    "Contains config.toml for the background service (gui-prefs.json is stored separately in your user config folder).",
  configFolderDescDefault: "Contains config.toml and gui-prefs.json.",
  btnOpenConfigFolder: "Open Config Folder",
  logsFolderLabel: "Logs folder",
  logsFolderDesc:
    "Diagnostic logs written by the vdpi service and desktop app.",
  btnOpenLogsFolder: "Open Logs Folder",
  desktopGuiLabel: "Desktop GUI",
  desktopGuiDescMac:
    "Exit the desktop window and remove any menu bar icon immediately.",
  desktopGuiDescDefault:
    "Exit the desktop window and remove any tray icon immediately.",
  btnQuitting: "Quitting...",
  btnQuitGui: "Quit GUI",

  // Uninstall confirm dialog
  uninstallTitle: "Uninstall background service?",
  uninstallDesc:
    "This removes the vdpi system service and stops background protection. Your configuration and GUI preferences will remain on disk.",
  cancel: "Cancel",

  // Action error/success fallbacks
  savePrefsFailed: "Failed to save GUI preferences.",
  installCancelled: "Service installation cancelled.",
  installFailed: "Failed to install background service.",
  installSuccess: "Background service installed.",
  uninstallCancelled: "Service uninstall cancelled.",
  uninstallFailed: "Failed to uninstall background service.",
  uninstallSuccess: "Background service uninstalled.",
  checkUpdatesFailed: "Could not check for updates.",
  openReleaseFailed: "Failed to open release page.",
  openConfigFolderFailed: "Failed to open config folder.",
  openLogsFolderFailed: "Failed to open logs folder.",
  quitGuiFailed: "Failed to quit GUI.",
} as const;

export type SettingsStringKey = keyof typeof en;
type SettingsDict = Record<SettingsStringKey, string>;

const tr: SettingsDict = {
  // Header
  title: "Ayarlar",
  subtitleMac:
    "Menü çubuğu davranışını, arka plan servisi kurulumunu, görünümü ve güncellemeleri yönetin.",
  subtitleDefault:
    "Sistem tepsisi davranışını, arka plan servisi kurulumunu, görünümü ve güncellemeleri yönetin.",

  // Window & Tray / Menu Bar card
  trayHeadingMac: "Pencere ve Menü Çubuğu",
  trayHeadingDefault: "Pencere ve Sistem Tepsisi",
  trayBadgeUnavailable: "Tepsi kullanılamıyor",
  trayBadgeMenuBarActive: "Menü çubuğu etkin",
  trayBadgeNoMenuBarIcon: "Menü çubuğu simgesi yok",
  trayBadgeActive: "Tepsi etkin",
  trayBadgeNoIcon: "Tepsi simgesi yok",
  linuxTrayNotice:
    "Bu Linux masaüstü ortamında sistem tepsisi desteği algılanmadı (StatusNotifier / AppIndicator gerekir). Tepsi seçenekleri simge göstermeyebilir.",
  keepInTrayLabelMac: "Kapatıldığında menü çubuğunda tut",
  keepInTrayLabelDefault: "Kapatıldığında sistem tepsisinde tut",
  keepInTrayDescOnMac:
    "Pencereyi kapatmak onu canlı durum noktası ve hızlı menüyle menü çubuğuna gizler.",
  keepInTrayDescOnDefault:
    "Pencereyi kapatmak onu canlı durum noktası ve hızlı menüyle sistem tepsisine gizler.",
  keepInTrayDescOffMac:
    "Pencereyi kapatmak, Dock veya menü çubuğunda simge bırakmadan arayüz uygulamasından tamamen çıkar.",
  keepInTrayDescOffDefault:
    "Pencereyi kapatmak, görev çubuğunda veya sistem tepsisinde simge bırakmadan arayüz uygulamasından tamamen çıkar.",
  minimizeToTrayLabelMac: "Menü çubuğuna küçült",
  minimizeToTrayLabelDefault: "Sistem tepsisine küçült",
  minimizeToTrayDescMac:
    "Küçültme işlemi pencereyi menü çubuğuna gizler ve menü çubuğu simgesini otomatik olarak etkinleştirir.",
  minimizeToTrayDescDefault:
    "Küçültme işlemi pencereyi sistem tepsisine gizler ve sistem tepsisi simgesini otomatik olarak etkinleştirir.",
  startMinimizedLabelMac: "Menü çubuğuna küçültülmüş başlat",
  startMinimizedLabelDefault: "Tepsiye küçültülmüş başlat",
  startMinimizedDescMac:
    "Ana pencereyi açmak yerine arayüzü menü çubuğunda gizli olarak başlatın.",
  startMinimizedDescDefault:
    "Ana pencereyi açmak yerine arayüzü sistem tepsisinde gizli olarak başlatın.",
  showTaskbarLabelMac: "Küçültüldüğünde Dock simgesini göster",
  showTaskbarLabelDefault: "Küçültüldüğünde görev çubuğu simgesini göster",
  showTaskbarDescMac:
    "Menü çubuğuna küçültülmüşken uygulama simgesini Dock'ta görünür tutun.",
  showTaskbarDescDefault:
    "Sistem tepsisine küçültülmüşken pencere düğmesini görev çubuğunda görünür tutun.",
  trayFooterNote:
    "Arayüzü kapatmak veya çıkmak, kuruluysa arka plandaki vdpi servisini durdurmaz.",

  // Background Service card
  serviceHeading: "Arka Plan Servisi",
  serviceStateRunning: "Çalışıyor",
  serviceStateStopped: "Durduruldu",
  serviceStateNotInstalled: "Kurulu Değil",
  serviceStateChecking: "Kontrol ediliyor...",
  serviceRowLabel: "vdpi sistem servisi",
  serviceBinaryPrefix: "İkili dosya:",
  serviceVersionNotInstalled: "Kurulu değil",
  serviceVersionUnknown: "Bilinmiyor",
  btnOpenInstallation: "Kuruluma Git",
  btnUpdateEngine: "Motoru Güncelle",
  btnUpdatingEngine: "Güncelleniyor...",
  btnInstalling: "Kuruluyor...",
  btnInstallService: "Arka Plan Servisini Kur",
  btnUninstalling: "Kaldırılıyor...",
  btnUninstallService: "Servisi Kaldır",
  serviceWintunMissingNote:
    "Windows'ta Tam PC (TUN) modu için wintun.dll gerekir. Kurulum sekmesinden wintun.dll ekleyin veya Proxy moduna geçin.",

  // Appearance card
  appearanceHeading: "Görünüm",
  themeLabel: "Tema",
  themeDesc:
    "İşletim sistemi temanızı izleyin veya koyu ya da açık moda sabitleyin.",
  themeSystem: "Sistem",
  themeDark: "Koyu",
  themeLight: "Açık",
  languageLabel: "Dil",
  languageDesc:
    "İşletim sistemi dilinizi izleyin veya İngilizce ya da Türkçe seçin.",
  languageSystem: "Sistem",
  languageEn: "English",
  languageTr: "Türkçe",

  // Updates & Local Data card
  updatesHeading: "Güncellemeler ve Yerel Veriler",
  desktopAppLabel: "Masaüstü uygulaması",
  currentVersionPrefix: "Mevcut sürüm",
  btnCheckingUpdates: "Kontrol ediliyor...",
  btnCheckUpdates: "Güncellemeleri Denetle",
  updateAvailablePrefix: "Güncelleme mevcut:",
  upToDate: "Güncel",
  viewRelease: "Sürümü görüntüle",
  installedPrefix: "Kurulu",
  latestPrefix: "en son",
  runningLatestBefore: "En son sürümü kullanıyorsunuz (",
  runningLatestAfter: ").",
  updateCheckFailed: "Güncelleme denetimi başarısız",
  configFolderLabel: "Yapılandırma klasörü",
  configFolderDescUnix:
    "Arka plan servisi için config.toml dosyasını içerir (gui-prefs.json kullanıcı yapılandırma klasörünüzde ayrı saklanır).",
  configFolderDescDefault: "config.toml ve gui-prefs.json dosyalarını içerir.",
  btnOpenConfigFolder: "Yapılandırma Klasörünü Aç",
  logsFolderLabel: "Günlük klasörü",
  logsFolderDesc:
    "vdpi servisi ve masaüstü uygulaması tarafından yazılan tanılama günlükleri.",
  btnOpenLogsFolder: "Günlük Klasörünü Aç",
  desktopGuiLabel: "Masaüstü Arayüzü",
  desktopGuiDescMac:
    "Masaüstü penceresinden çıkın ve menü çubuğu simgesini hemen kaldırın.",
  desktopGuiDescDefault:
    "Masaüstü penceresinden çıkın ve sistem tepsisi simgesini hemen kaldırın.",
  btnQuitting: "Çıkılıyor...",
  btnQuitGui: "Arayüzden Çık",

  // Uninstall confirm dialog
  uninstallTitle: "Arka plan servisi kaldırılsın mı?",
  uninstallDesc:
    "Bu işlem vdpi sistem servisini kaldırır ve arka plan korumasını durdurur. Yapılandırmanız ve arayüz tercihleriniz diskte kalır.",
  cancel: "İptal",

  // Action error/success fallbacks
  savePrefsFailed: "Arayüz tercihleri kaydedilemedi.",
  installCancelled: "Servis kurulumu iptal edildi.",
  installFailed: "Arka plan servisi kurulamadı.",
  installSuccess: "Arka plan servisi kuruldu.",
  uninstallCancelled: "Servis kaldırma işlemi iptal edildi.",
  uninstallFailed: "Arka plan servisi kaldırılamadı.",
  uninstallSuccess: "Arka plan servisi kaldırıldı.",
  checkUpdatesFailed: "Güncellemeler denetlenemedi.",
  openReleaseFailed: "Sürüm sayfası açılamadı.",
  openConfigFolderFailed: "Yapılandırma klasörü açılamadı.",
  openLogsFolderFailed: "Günlük klasörü açılamadı.",
  quitGuiFailed: "Arayüzden çıkılamadı.",
};

export const SETTINGS_STRINGS: {
  en: SettingsDict;
  tr: SettingsDict;
} = { en, tr };

export const tSettings = createTranslator<SettingsDict>(SETTINGS_STRINGS);
