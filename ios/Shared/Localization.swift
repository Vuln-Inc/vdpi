import Foundation
#if canImport(SwiftUI)
import SwiftUI
#endif

public enum ResolvedLanguage: String, Equatable, Sendable {
    case en
    case tr

    public var locale: Locale {
        switch self {
        case .en: return Locale(identifier: "en_US")
        case .tr: return Locale(identifier: "tr_TR")
        }
    }
}

/// Complete English and Turkish localization catalog shared across `VdpiApp`,
/// `VdpiPacketTunnel`, and `VdpiAppIntents`.
public enum L10n {
    /// Resolves `.system` using `preferredLanguages.first` (`"tr"` prefix -> Turkish, else English).
    public static func resolve(
        _ language: AppLanguage,
        preferredLanguages: [String] = Locale.preferredLanguages
    ) -> ResolvedLanguage {
        switch language {
        case .en:
            return .en
        case .tr:
            return .tr
        case .system:
            if preferredLanguages.first?.lowercased().hasPrefix("tr") == true {
                return .tr
            }
            return .en
        }
    }

    public static func isTurkish(
        _ language: AppLanguage,
        preferredLanguages: [String] = Locale.preferredLanguages
    ) -> Bool {
        resolve(language, preferredLanguages: preferredLanguages) == .tr
    }

    public static func pick(
        _ language: AppLanguage,
        en: String,
        tr: String,
        preferredLanguages: [String] = Locale.preferredLanguages
    ) -> String {
        isTurkish(language, preferredLanguages: preferredLanguages) ? tr : en
    }

    public static func catalog(
        for language: AppLanguage,
        preferredLanguages: [String] = Locale.preferredLanguages
    ) -> Catalog {
        Catalog(resolved: resolve(language, preferredLanguages: preferredLanguages))
    }

    public struct Catalog: Equatable, Sendable {
        public let resolved: ResolvedLanguage

        public var isTurkish: Bool { resolved == .tr }
        public var locale: Locale { resolved.locale }

        public init(resolved: ResolvedLanguage) {
            self.resolved = resolved
        }

        public init(
            language: AppLanguage,
            preferredLanguages: [String] = Locale.preferredLanguages
        ) {
            self.resolved = L10n.resolve(language, preferredLanguages: preferredLanguages)
        }

        private func t(_ en: String, _ tr: String) -> String {
            isTurkish ? tr : en
        }

        // MARK: - Common & Tabs

        public var tabTunnel: String { t("Tunnel", "Tünel") }
        public var tabSettings: String { t("Settings", "Ayarlar") }

        public var on: String { t("On", "Açık") }
        public var off: String { t("Off", "Kapalı") }
        public var done: String { t("Done", "Bitti") }
        public var cancel: String { t("Cancel", "Vazgeç") }
        public var dismiss: String { t("Dismiss", "Kapat") }
        public var apply: String { t("Apply", "Uygula") }
        public var add: String { t("Add", "Ekle") }
        public var customDoh: String { t("Custom DoH", "Özel DoH") }

        // MARK: - Theme & Language Options

        public var themeSystem: String { t("System", "Sistem") }
        public var themeDark: String { t("Dark", "Koyu") }
        public var themeLight: String { t("Light", "Açık") }
        public var languageSystem: String { t("System", "Sistem") }

        // MARK: - Desync Modes

        public var desyncModeComboLabel: String { t("Combo", "Kombo") }
        public var desyncModeTlsRecordLabel: String { t("TLS Record", "TLS Kaydı") }
        public var desyncModeFragmentLabel: String { t("Fragment", "Parçalama") }
        public var desyncModeSplitLabel: String { t("Split", "Bölme") }

        public var desyncModeComboSubtitle: String {
            t(
                "4-record TLS split + adaptive 7-stage auto-heal",
                "4 kayıtlı TLS bölme + uyarlanabilir 7 aşamalı otomatik onarım"
            )
        }

        public var desyncModeTlsRecordSubtitle: String {
            t(
                "Split ClientHello across two RFC TLS records",
                "ClientHello paketini iki RFC TLS kaydına böler"
            )
        }

        public var desyncModeFragmentSubtitle: String {
            t(
                "Single outer TLS record sliced at SNI boundaries",
                "Tek dış TLS kaydını SNI sınırlarında dilimler"
            )
        }

        public var desyncModeSplitSubtitle: String {
            t(
                "Initial chunk-byte TCP split on first flight",
                "İlk gönderimde bayt parçalı TCP bölme uygular"
            )
        }

        // MARK: - Strategy Stage Labels

        public var stageCombo: String { t("Combo", "Kombo") }
        public var stageOobSni: String { t("OOB SNI", "OOB SNI") }
        public var stageMultiOob: String { t("Multi + OOB", "Çoklu + OOB") }
        public var stageFineFragment: String { t("Fine Fragment", "İnce Parçalama") }
        public var stageDeepStorm: String { t("Deep Storm", "Derin Fırtına") }
        public var stageSlowSni: String { t("Slow SNI", "Yavaş SNI") }
        public var stagePassthrough: String { t("Passthrough", "Doğrudan Geçiş") }

        // MARK: - Pending Change Field Labels

        public var fieldMode: String { t("Mode", "Mod") }
        public var fieldChunk: String { t("Chunk", "Parça") }
        public var fieldDns: String { "DNS" }
        public var fieldDoh: String { "DoH" }
        public var fieldIpv4: String { "IPv4" }
        public var fieldQuic: String { "QUIC" }
        public var fieldMtu: String { "MTU" }
        public var fieldBypass: String { t("Bypass", "İstisna") }

        public func pendingMoreSummary(head: String, remaining: Int) -> String {
            isTurkish ? "\(head) +\(remaining) daha" : "\(head) +\(remaining) more"
        }

        // MARK: - Tunnel Phase & Hero

        public var phaseStandby: String { t("Standby", "Beklemede") }
        public var phaseConnecting: String { t("Connecting", "Bağlanıyor") }
        public var phaseProtected: String { t("Protected", "Korumalı") }
        public var phaseStopping: String { t("Stopping", "Durduruluyor") }
        public var phaseError: String { t("Error", "Hata") }

        public var heroConnected: String { t("Connected", "Bağlı") }
        public var heroConnecting: String { t("Connecting", "Bağlanıyor") }
        public var heroDisconnecting: String { t("Disconnecting", "Bağlantı Kesiliyor") }
        public var heroNotConnected: String { t("Not Connected", "Bağlı Değil") }
        public var heroConnectionError: String { t("Connection Error", "Bağlantı Hatası") }

        public var buttonConnect: String { t("Connect", "Bağlan") }
        public var buttonDisconnect: String { t("Disconnect", "Bağlantıyı Kes") }
        public var buttonDisconnecting: String { t("Disconnecting...", "Bağlantı Kesiliyor...") }

        public var subtitleEstablishing: String {
            t("Establishing local tunnel...", "Yerel tünel kuruluyor...")
        }
        public var subtitleClosing: String {
            t("Closing local tunnel...", "Yerel tünel kapatılıyor...")
        }
        public var subtitleReady: String {
            t("Local anti-DPI tunnel ready", "Yerel anti-DPI tüneli hazır")
        }

        public var accessibilityCancelConnectionHint: String {
            t("Double tap to cancel connection", "Bağlantıyı iptal etmek için çift dokunun")
        }

        // MARK: - Tunnel Telemetry, Profile & Actions

        public var sectionConnection: String { t("Connection", "Bağlantı") }
        public var sectionProfile: String { t("Profile", "Profil") }
        public var sectionActions: String { t("Actions", "İşlemler") }

        public var metricDownload: String { t("Download", "İndirme") }
        public var metricUpload: String { t("Upload", "Yükleme") }
        public var metricUptime: String { t("Uptime", "Çalışma Süresi") }
        public var metricActivity: String { t("Activity", "Etkinlik") }
        public var metricStrategy: String { t("Strategy", "Strateji") }
        public var metricDns: String { "DNS" }
        public var metricQuicBlocked: String { t("QUIC Blocked", "Engellenen QUIC") }
        public var quicAllowed: String { t("Allowed", "İzin Verildi") }

        public func accessibilityActivity(rate: String) -> String {
            isTurkish ? "Etkinlik, \(rate)" : "Activity, \(rate)"
        }

        public var profileMode: String { t("Mode", "Mod") }
        public var profileQuicBlocking: String { t("QUIC Blocking", "QUIC Engelleme") }
        public var profileOnDemand: String { t("On-Demand", "İsteğe Bağlı") }

        public var clearEngineCache: String { t("Clear Engine Cache", "Motor Önbelleğini Temizle") }
        public var cleared: String { t("Cleared", "Temizlendi") }

        // MARK: - Floating Chrome & Reconnect Banner

        public var settingsChangedTitle: String { t("Settings Changed", "Ayarlar Değişti") }
        public var reconnectToApply: String { t("Reconnect to apply", "Uygulamak için yeniden bağlanın") }
        public func reconnectToApply(summary: String) -> String {
            "\(reconnectToApply) · \(summary)"
        }
        public var reconnectButton: String { t("Reconnect", "Yeniden Bağlan") }
        public var accessibilityReconnectingTunnel: String { t("Reconnecting tunnel", "Tünel yeniden bağlanıyor") }
        public var accessibilityReconnectTunnel: String { t("Reconnect tunnel", "Tüneli yeniden bağla") }
        public var accessibilityDisconnectTunnel: String { t("Disconnect tunnel", "Tünel bağlantısını kes") }

        public var accessoryConnected: String { t("Connected", "Bağlı") }
        public var accessoryConnecting: String { t("Connecting...", "Bağlanıyor...") }
        public var accessoryDisconnecting: String { t("Disconnecting...", "Bağlantı kesiliyor...") }
        public var accessoryTunnelError: String { t("Tunnel Error", "Tünel Hatası") }
        public var accessoryDisconnected: String { t("Disconnected", "Bağlı Değil") }

        public var accessoryStartingSubtitle: String {
            t("Starting TLS desync & DoH...", "TLS desync ve DoH başlatılıyor...")
        }
        public var accessoryClosingSubtitle: String {
            t("Closing tunnel interface...", "Tünel arayüzü kapatılıyor...")
        }
        public var tapToInspect: String { t("Tap to inspect", "İncelemek için dokunun") }

        public func accessibilitySwitchToTunnel(title: String, subtitle: String) -> String {
            isTurkish
                ? "\(title), \(subtitle). Tünel sekmesine geç"
                : "\(title), \(subtitle). Switch to Tunnel"
        }

        public var tabTunnelConnectedPending: String {
            t("Tunnel, connected, settings pending", "Tünel, bağlı, bekleyen ayarlar var")
        }
        public var tabTunnelConnected: String { t("Tunnel, connected", "Tünel, bağlı") }
        public var tabTunnelConnecting: String { t("Tunnel, connecting", "Tünel, bağlanıyor") }
        public var tabTunnelError: String { t("Tunnel, error", "Tünel, hata") }

        // MARK: - Update Banner & Settings Update Row

        public func updateAvailableBanner(version: String) -> String {
            isTurkish ? "Güncelleme mevcut · \(version)" : "Update available · \(version)"
        }
        public func updateAvailableRowTitle(version: String) -> String {
            isTurkish ? "Güncelleme Mevcut · \(version)" : "Update Available · \(version)"
        }
        public func updateAvailableRowSubtitle(currentVersion: String) -> String {
            isTurkish
                ? "Mevcut \(currentVersion) · GitHub Sürümünü Aç"
                : "Current \(currentVersion) · Open GitHub Release"
        }
        public func accessibilityOpenRelease(version: String) -> String {
            isTurkish
                ? "\(version) sürümünü GitHub'da aç"
                : "Open \(version) release on GitHub"
        }
        public func accessibilityUpdateRow(version: String) -> String {
            isTurkish
                ? "Güncelleme mevcut, \(version). GitHub sürümünü aç"
                : "Update available, \(version). Open GitHub release"
        }
        public var accessibilityDismissUpdate: String {
            t("Dismiss update notice", "Güncelleme bildirimini kapat")
        }
        public var checkForUpdates: String { t("Check for Updates", "Güncellemeleri Denetle") }
        public var accessibilityCheckingUpdates: String { t("Checking for updates", "Güncellemeler denetleniyor") }
        public var updateCheckFailed: String { t("Check failed", "Kontrol başarısız") }
        public var updateUpToDate: String { t("Up to date", "Güncel") }
        public func updateAvailableInline(version: String) -> String {
            isTurkish ? "Güncelleme mevcut: v\(version)" : "Update available: v\(version)"
        }

        // MARK: - Diagnostics & Engine Logs Sheets

        public var diagnosticsTitle: String { t("Diagnostics", "Tanılama") }
        public var engineLogsTitle: String { t("Engine Logs", "Motor Günlükleri") }
        public var diagnosticsSectionChecks: String { t("Checks", "Kontroller") }
        public var rerunButton: String { t("Re-run", "Tekrar Çalıştır") }
        public var accessibilityShareDiagnostics: String {
            t("Share diagnostics report", "Tanılama raporunu paylaş")
        }
        public var runningDiagnosticsTitle: String { t("Running Diagnostics", "Tanılama Çalıştırılıyor") }
        public var runningDiagnosticsSubtitle: String {
            t("Testing DNS, DoH, TLS, and QUIC paths.", "DNS, DoH, TLS ve QUIC yolları test ediliyor.")
        }
        public var diagnosticsFailedTitle: String { t("Diagnostics Failed", "Tanılama Başarısız") }
        public var diagnosticsEmptyMessage: String {
            t(
                "Tap Re-run to verify live DNS, DoH, and TLS desync probes.",
                "Canlı DNS, DoH ve TLS desync testlerini doğrulamak için Tekrar Çalıştır'a dokunun."
            )
        }

        public func doctorCheckName(_ raw: String) -> String {
            guard isTurkish else { return raw }
            switch raw {
            case "Engine Init": return "Motor Başlatma"
            case "DNS Ring": return "DNS Halkası"
            default: return raw
            }
        }

        public func diagnosticsAllPassed(total: Int) -> String {
            isTurkish ? "\(total) kontrolün tamamı başarılı" : "All \(total) checks passed"
        }
        public func diagnosticsPartialPassed(passed: Int, total: Int) -> String {
            isTurkish ? "\(total) kontrolden \(passed) tanesi başarılı" : "\(passed) of \(total) passed"
        }
        public var diagnosticsHealthy: String { t("Healthy", "Sağlıklı") }
        public func diagnosticsFailedCount(_ failed: Int) -> String {
            isTurkish ? "\(failed) başarısız" : "\(failed) failed"
        }
        public func accessibilityDiagnosticsSummary(passed: Int, total: Int, failed: Int) -> String {
            if failed == 0 {
                return isTurkish
                    ? "\(total) kontrolün tamamı başarılı, sağlıklı"
                    : "All \(total) checks passed, healthy"
            }
            return isTurkish
                ? "\(total) kontrolden \(passed) tanesi başarılı, \(failed) başarısız"
                : "\(passed) of \(total) checks passed, \(failed) failed"
        }
        public func diagnosticsCheckAccessibility(
            name: String,
            passed: Bool,
            latencyMs: UInt64,
            detail: String
        ) -> String {
            if isTurkish {
                let status = passed ? "Başarılı" : "Başarısız"
                return "\(name), \(status), \(latencyMs) milisaniye, \(detail)"
            }
            let status = passed ? "Passed" : "Failed"
            return "\(name), \(status), \(latencyMs) milliseconds, \(detail)"
        }
        public func diagnosticsIssuesFooter(failedCount: Int) -> String {
            if isTurkish {
                return "\(failedCount) sorun tespit edildi - DNS veya ağ ayarlarınızı kontrol edin."
            }
            let noun = failedCount == 1 ? "issue" : "issues"
            return "\(failedCount) \(noun) detected - check DNS or network settings."
        }

        public var accessibilityCopiedLogs: String { t("Copied logs", "Günlükler kopyalandı") }
        public var accessibilityCopyLogs: String { t("Copy logs", "Günlükleri kopyala") }
        public var accessibilityShareLogs: String { t("Share logs", "Günlükleri paylaş") }
        public var noEngineLogsTitle: String { t("No Engine Logs Yet", "Henüz Motor Günlüğü Yok") }
        public var noEngineLogsSubtitle: String {
            t("Connect the tunnel to record activity.", "Etkinliği kaydetmek için tüneli bağlayın.")
        }

        // MARK: - Diagnostics Share Report

        public var reportHeader: String { t("vdpi Diagnostics Report", "vdpi Tanılama Raporu") }
        public var reportAppVersion: String { t("App Version", "Uygulama Sürümü") }
        public var reportEngineVersion: String { t("Engine Version", "Motor Sürümü") }
        public var reportStatus: String { t("Status", "Durum") }
        public var reportMode: String { t("Mode", "Mod") }
        public var reportQuicBlocking: String { t("QUIC Blocking", "QUIC Engelleme") }
        public var reportIpv4Only: String { t("IPv4 Only", "Yalnızca IPv4") }
        public var reportBypassRules: String { t("Bypass Rules", "İstisna Kuralları") }
        public var reportProbesRunning: String { t("Diagnostics Probes: Running...", "Tanılama Testleri: Çalışıyor...") }
        public func reportProbesError(_ detail: String) -> String {
            isTurkish ? "Tanılama Testleri: Hata - \(detail)" : "Diagnostics Probes: Error - \(detail)"
        }
        public func reportProbesPassedHeader(passed: Int, total: Int) -> String {
            isTurkish
                ? "Tanılama Testleri (\(passed)/\(total) başarılı):"
                : "Diagnostics Probes (\(passed)/\(total) passed):"
        }
        public var reportProbesNotRun: String { t("Diagnostics Probes: Not run", "Tanılama Testleri: Çalıştırılmadı") }
        public var reportBadgePass: String { t("PASS", "BAŞARILI") }
        public var reportBadgeFail: String { t("FAIL", "BAŞARISIZ") }

        // MARK: - Settings Screen

        public var accessibilityDismissKeyboard: String { t("Dismiss keyboard", "Klavyeyi kapat") }

        public var sectionDesyncEngine: String { t("Desync Engine", "Desync Motoru") }
        public var chunkSizeLabel: String { t("Chunk Size", "Parça Boyutu") }
        public var accessibilityDecreaseChunk: String { t("Decrease chunk size", "Parça boyutunu azalt") }
        public var accessibilityIncreaseChunk: String { t("Increase chunk size", "Parça boyutunu artır") }
        public func accessibilityChunkSizeBytes(_ bytes: Int) -> String {
            isTurkish ? "Parça boyutu \(bytes) bayt" : "Chunk size \(bytes) bytes"
        }
        public var desyncFooter: String {
            t(
                "Splits outbound TLS ClientHello packets into smaller byte chunks (1-64 B) to evade deep packet inspection.",
                "Derin paket incelemesini (DPI) aşmak için giden TLS ClientHello paketlerini daha küçük bayt parçalarına (1-64 B) böler."
            )
        }

        public var sectionDnsPrivacy: String { t("DNS & Privacy", "DNS ve Gizlilik") }
        public var customDnsPlaceholder: String {
            t("Custom IP or https:// DoH URL", "Özel IP veya https:// DoH URL")
        }
        public var accessibilityActiveCustomDns: String { t("Active custom DNS", "Etkin özel DNS") }
        public var dnsValidationError: String {
            t(
                "Enter an IPv4, IPv6, or https:// DoH URL",
                "Geçerli bir IPv4, IPv6 veya https:// DoH URL girin"
            )
        }
        public var toggleDoh: String { t("DNS over HTTPS", "HTTPS Üzerinden DNS") }
        public var toggleDohForcedSubtitle: String {
            t(
                "Always enabled for custom https:// resolvers",
                "Özel https:// çözümleyiciler için her zaman etkindir"
            )
        }
        public var toggleBlockQuic: String { t("Block QUIC", "QUIC Engelle") }
        public var toggleIpv4Only: String { t("IPv4 Only", "Yalnızca IPv4") }
        public var dnsFooter: String {
            t(
                "Encrypts resolver lookups with DoH and blocks UDP/443 QUIC so traffic falls back to TCP where TLS desync applies.",
                "DNS sorgularını DoH ile şifreler ve trafiğin TLS desync uygulanabilen TCP'ye dönmesi için UDP/443 QUIC protokolünü engeller."
            )
        }

        public var sectionTunnel: String { t("Tunnel", "Tünel") }
        public var toggleConnectOnDemand: String { t("Connect On-Demand", "İsteğe Bağlı Bağlan") }
        public var tunnelFooter: String {
            t(
                "Automatically keeps the vdpi tunnel active when switching between Wi-Fi and cellular networks.",
                "Wi-Fi ve hücresel ağlar arasında geçiş yaparken vdpi tünelini otomatik olarak etkin tutar."
            )
        }

        public var sectionBypassDomains: String { t("Bypass Domains", "İstisna Alan Adları") }
        public var bypassPlaceholder: String {
            t("Add domain (e.g. example.com)", "Alan adı ekle (örn. example.com)")
        }
        public var bypassInvalidError: String {
            t(
                "Enter a valid domain such as example.com or *.example.com",
                "example.com veya *.example.com gibi geçerli bir alan adı girin"
            )
        }
        public var bypassDuplicateError: String {
            t("Already in bypass list", "Zaten istisna listesinde")
        }
        public func accessibilityRemoveDomain(_ domain: String) -> String {
            isTurkish ? "\(domain) alan adını kaldır" : "Remove \(domain)"
        }
        public var bypassFooter: String {
            t(
                "Matching domains and subdomains skip TLS desync. Local networks, banking, and government portals are bypassed automatically.",
                "Eşleşen alan adları ve alt alan adları TLS desync dışına alınır. Yerel ağlar, bankacılık ve devlet portalları otomatik olarak hariç tutulur."
            )
        }

        public var sectionAppearance: String { t("Appearance", "Görünüm") }
        public var appearanceFooter: String {
            t(
                "System matches your device Light and Dark appearance automatically.",
                "Sistem seçeneği, aygıtınızın Açık ve Koyu görünümüne otomatik olarak uyum sağlar."
            )
        }

        public var sectionLanguage: String { t("Language", "Dil") }
        public var languageFooter: String {
            t(
                "System follows your device language automatically.",
                "Sistem seçeneği, aygıt dilinizi otomatik olarak takip eder."
            )
        }

        public var sectionBackupRestore: String { t("Backup & Restore", "Yedekle ve Geri Yükle") }
        public var exportSettings: String { t("Export Settings", "Ayarları Dışa Aktar") }
        public var importSettings: String { t("Import Settings", "Ayarları İçe Aktar") }
        public var backupFooter: String {
            t(
                "Save your desync, DNS, and bypass configuration as JSON or restore from a previous backup.",
                "Desync, DNS ve istisna yapılandırmanızı JSON olarak kaydedin veya önceki bir yedekten geri yükleyin."
            )
        }

        public var sectionUpdates: String { t("Updates", "Güncellemeler") }
        public var resetToDefaults: String { t("Reset to Defaults", "Varsayılanlara Sıfırla") }
        public var resetConfirmTitle: String {
            t(
                "Reset all tunnel settings to defaults?",
                "Tüm tünel ayarları varsayılanlara sıfırlansın mı?"
            )
        }

        public var sectionAbout: String { t("About", "Hakkında") }
        public var githubRepository: String { t("GitHub Repository", "GitHub Deposu") }
        public var accessibilityOpenGithub: String {
            t("Open vdpi GitHub repository", "vdpi GitHub deposunu aç")
        }

        // MARK: - Toasts & Errors

        public var toastSettingsReset: String {
            t("Settings reset to defaults", "Ayarlar varsayılanlara sıfırlandı")
        }
        public var toastAppliedSettings: String {
            t("Applied updated settings", "Güncel ayarlar uygulandı")
        }
        public var toastReconnectTimedOut: String {
            t("Reconnect timed out - try again", "Yeniden bağlanma zaman aşımına uğradı - tekrar deneyin")
        }
        public var toastClearedCaches: String {
            t("Cleared TLS & DNS caches", "TLS ve DNS önbellekleri temizlendi")
        }
        public var toastExtensionUnreachable: String {
            t("Could not reach tunnel extension", "Tünel eklentisine ulaşılamadı")
        }
        public var toastClearedTlsStrategies: String {
            t("Cleared cached TLS strategies", "Önbellekteki TLS stratejileri temizlendi")
        }
        public var toastUpdatedDns: String {
            t("Updated DNS resolver", "DNS çözümleyici güncellendi")
        }
        public var toastExportedSettings: String {
            t("Exported settings", "Ayarlar dışa aktarıldı")
        }
        public var toastExportFailed: String {
            t("Export failed", "Dışa aktarma başarısız")
        }
        public var toastCouldNotExport: String {
            t("Could not export settings", "Ayarlar dışa aktarılamadı")
        }
        public var toastImportedSettings: String {
            t("Imported settings", "Ayarlar içe aktarıldı")
        }
        public var toastImportFailed: String {
            t("Import failed", "İçe aktarma başarısız")
        }
        public var toastSettingsFileTooLarge: String {
            t("Settings file is too large (max 256 KB).", "Ayar dosyası çok büyük (en fazla 256 KB).")
        }
        public var toastInvalidSettingsFile: String {
            t("Invalid settings file", "Geçersiz ayar dosyası")
        }

        public var errorPreviousTunnelStopTimeout: String {
            t(
                "Previous tunnel did not stop in time. Try again.",
                "Önceki tünel zamanında durdurulamadı. Tekrar deneyin."
            )
        }
        public var errorDiagnosticsTimeout: String {
            t(
                "Diagnostics timed out or the tunnel extension did not respond.",
                "Tanılama zaman aşımına uğradı veya tünel eklentisi yanıt vermedi."
            )
        }
        public var errorDiagnosticsNoResults: String {
            t(
                "Native diagnostics returned no probe results.",
                "Yerel tanılama herhangi bir test sonucu döndürmedi."
            )
        }
        public var errorEngineNotRunning: String {
            t(
                "Tunnel engine is not running. Tap Connect to restart.",
                "Tünel motoru çalışmıyor. Yeniden başlatmak için Bağlan'a dokunun."
            )
        }

        public var importErrorEmptyPayload: String {
            t("Settings backup is empty.", "Ayar yedeği boş.")
        }
        public var importErrorInvalidJson: String {
            t("Settings backup is not valid JSON.", "Ayar yedeği geçerli bir JSON değil.")
        }
        public var importErrorUnrecognizedFormat: String {
            t(
                "JSON does not contain recognized vdpi settings.",
                "JSON dosyası tanınan vdpi ayarlarını içermiyor."
            )
        }
        public func importErrorInvalidDns(_ addr: String) -> String {
            isTurkish
                ? "Ayar yedeğindeki DNS adresi geçersiz: \(addr)"
                : "Invalid DNS address in settings backup: \(addr)"
        }

        // MARK: - App Intents Dialogs

        public var intentAlreadyConnected: String {
            t("vdpi is already connected.", "vdpi zaten bağlı.")
        }
        public var intentConnected: String {
            t("Connected vdpi.", "vdpi bağlandı.")
        }
        public var intentAlreadyDisconnected: String {
            t("vdpi is already disconnected.", "vdpi zaten bağlı değil.")
        }
        public var intentDisconnected: String {
            t("Disconnected vdpi.", "vdpi bağlantısı kesildi.")
        }
    }
}

#if canImport(SwiftUI)
private struct AppLanguageKey: EnvironmentKey {
    static let defaultValue: AppLanguage = .system
}

public extension EnvironmentValues {
    var appLanguage: AppLanguage {
        get { self[AppLanguageKey.self] }
        set { self[AppLanguageKey.self] = newValue }
    }
}
#endif
