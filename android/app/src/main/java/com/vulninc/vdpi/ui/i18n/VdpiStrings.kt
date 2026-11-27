package com.vulninc.vdpi.ui.i18n

import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import com.vulninc.vdpi.data.AppLanguage
import com.vulninc.vdpi.data.SplitTunnelMode
import com.vulninc.vdpi.data.ThemePreference
import com.vulninc.vdpi.engine.DesyncMode
import java.util.Locale

@Immutable
data class VdpiStrings(
    val languageCode: String,

    // ── Navigation Tabs ──
    val tabTunnel: String,
    val tabApps: String,
    val tabSettings: String,

    // ── Common Actions & Values ──
    val actionConnect: String,
    val actionDisconnect: String,
    val actionReconnect: String,
    val actionDone: String,
    val actionDismiss: String,
    val actionUndo: String,
    val actionApply: String,
    val actionAdd: String,
    val actionOpen: String,
    val actionDownload: String,
    val actionCopy: String,
    val actionCopied: String,
    val actionRerun: String,
    val actionClearSearch: String,
    val valueEnabled: String,
    val valueOff: String,
    val valueAllowed: String,
    val valueAllApps: String,
    val customDohLabel: String,

    // ── Tunnel Status & Hero ──
    val statusConnected: String,
    val statusConnecting: String,
    val statusConnectingEllipsis: String,
    val statusNotConnected: String,
    val statusDisconnected: String,
    val statusConnectionError: String,
    val statusTunnelError: String,
    val statusPassed: String,
    val statusFailed: String,
    val heroEstablishingTunnel: String,
    val heroTunnelReady: String,
    val heroTunnelStoppedUnexpectedly: String,

    // ── Floating Chrome & Reconnect ──
    val reconnectSettingsChanged: String,
    val reconnectToApply: String,
    val reconnectToApplyPrefix: String,
    val accessoryEstablishingTunnel: String,
    val accessoryConnectionInterrupted: String,
    val accessoryTapToOpen: String,
    val cdReconnectTunnel: String,
    val cdDisconnectTunnel: String,
    val changeKeyMode: String,
    val changeKeyChunk: String,
    val changeKeyDns: String,
    val changeKeyDoh: String,
    val changeKeyIpv4: String,
    val changeKeyQuic: String,
    val changeKeyBypass: String,
    val changeKeyApps: String,

    // ── Tunnel Dashboard Telemetry & Profile ──
    val sectionConnection: String,
    val sectionProfile: String,
    val metricDownload: String,
    val metricUpload: String,
    val metricUptime: String,
    val metricActivity: String,
    val metricStrategy: String,
    val metricMode: String,
    val metricDns: String,
    val metricQuicBlocked: String,
    val metricQuicBlocking: String,
    val metricDroppedPackets: String,
    val metricSplitTunnel: String,
    val cdLiveThroughputPrefix: String,
    val splitNoneProtected: String,
    val splitBypassedSuffix: String,
    val splitRoutedSuffix: String,

    // ── Stage Labels ──
    val stageWord: String,
    val stageCombo: String,
    val stageOobSni: String,
    val stageMultiOob: String,
    val stageFineFragment: String,
    val stageDeepStorm: String,
    val stageSlowSni: String,
    val stagePassthrough: String,

    // ── Diagnostics & Engine Logs Sheets ──
    val diagnosticsTitle: String,
    val diagnosticsChecksHeader: String,
    val diagnosticsRunning: String,
    val diagnosticsEmptyReturned: String,
    val diagnosticsTapToRun: String,
    val diagnosticsShareSubject: String,
    val diagnosticsShareChooser: String,
    val cdShareDiagnostics: String,
    val logsTitle: String,
    val logsEmptyTitle: String,
    val logsEmptySubtitle: String,
    val logsClipboardLabel: String,

    // ── Apps (Split Tunneling) ──
    val appsTitle: String,
    val splitModeBypassSelected: String,
    val splitModeOnlySelected: String,
    val appsBypassSelectedFooter: String,
    val appsOnlySelectedFooter: String,
    val cdResetSelectedApps: String,
    val filterAll: String,
    val filterSelected: String,
    val filterSystem: String,
    val badgeSystem: String,
    val appsLoading: String,
    val appsEmptySelectedTitle: String,
    val appsEmptySearchTitle: String,
    val appsEmptyAllTitle: String,
    val appsEmptySelectedSubtitle: String,
    val appsEmptySearchSubtitle: String,
    val appsEmptyAllSubtitle: String,
    val appsSearchPlaceholder: String,
    val cdClearSearch: String,

    // ── Settings Screen ──
    val settingsTitle: String,
    val sectionDesyncEngine: String,
    val desyncComboLabel: String,
    val desyncComboSummary: String,
    val desyncTlsRecordLabel: String,
    val desyncTlsRecordSummary: String,
    val desyncFragmentLabel: String,
    val desyncFragmentSummary: String,
    val desyncSplitLabel: String,
    val desyncSplitSummary: String,
    val labelChunkSize: String,
    val cdDecreaseChunkSize: String,
    val cdIncreaseChunkSize: String,
    val footerDesyncEngine: String,

    val sectionDnsPrivacy: String,
    val placeholderCustomDns: String,
    val errorInvalidDns: String,
    val labelDoh: String,
    val subtitleDohRequired: String,
    val subtitleDohDefault: String,
    val labelBlockQuic: String,
    val subtitleBlockQuic: String,
    val labelIpv4Only: String,
    val subtitleIpv4Only: String,
    val footerDnsPrivacy: String,

    val sectionBypassDomains: String,
    val placeholderAddDomain: String,
    val errorInvalidDomain: String,
    val footerBypassDomains: String,

    val sectionAppearance: String,
    val themeSystem: String,
    val themeDark: String,
    val themeLight: String,

    val sectionLanguage: String,
    val languageSystem: String,
    val languageEnglish: String,
    val languageTurkish: String,

    val sectionSystem: String,
    val labelClearCache: String,
    val subtitleClearCache: String,
    val labelSystemVpn: String,
    val subtitleSystemVpn: String,

    val sectionBackupRestore: String,
    val labelExportSettings: String,
    val subtitleExportSettings: String,
    val labelImportSettings: String,
    val subtitleImportSettings: String,
    val footerBackupRestore: String,

    val sectionUpdates: String,
    val updateAvailable: String,
    val updateAvailableTitle: String,
    val subtitleOpenRelease: String,
    val labelCheckForUpdates: String,
    val updateUpToDate: String,
    val updateCheckFailed: String,
    val cdDismissUpdate: String,

    val sectionAbout: String,
    val labelGitHubRepo: String,

    // ── Feedback & ViewModel Messages ──
    val feedbackVpnPermissionDenied: String,
    val feedbackVpnPermissionRequired: String,
    val feedbackExportSerializeFailed: String,
    val feedbackSettingsExported: String,
    val feedbackSettingsExportFailed: String,
    val feedbackImportFileTooLarge: String,
    val feedbackImportReadFailed: String,
    val feedbackImportFileEmpty: String,
    val feedbackFilePickerUnavailable: String,
    val feedbackSystemVpnUnavailable: String,
    val feedbackCacheCleared: String,
    val feedbackCacheClearFailed: String,
    val importInvalidJson: String,
    val importSuccess: String,
    val importSuccessReconnect: String,

    // ── VPN Service, Notifications, Tile & Widget ──
    val notificationChannelName: String,
    val notificationChannelDesc: String,
    val notificationActionDisconnect: String,
    val notificationActionReconnect: String,
    val notificationTitleConnected: String,
    val notificationTitleConnecting: String,
    val notificationSubtitleConnecting: String,
    val notificationPermissionHint: String,
    val notificationSettingsAction: String,
    val errorBackgroundStartBlocked: String,
    val errorNativeEngineLoadFailed: String,
    val errorVpnInterfaceFailed: String,
    val errorEngineStartFailed: String,
    val errorEngineExitedImmediately: String,
    val errorVpnBackgroundStart: String,
    val errorVpnReconnect: String,
    val tileStarting: String,
    val tileOff: String,
    val widgetStatusConnected: String,
    val widgetStatusConnecting: String,
    val widgetStatusOff: String,
    val widgetStatusError: String,
    val widgetActionConnect: String,
    val widgetActionDisconnect: String,
) {
    val isTurkish: Boolean
        get() = languageCode == "tr"

    fun desyncModeLabel(mode: DesyncMode): String = when (mode) {
        DesyncMode.COMBO -> desyncComboLabel
        DesyncMode.TLS_RECORD -> desyncTlsRecordLabel
        DesyncMode.FRAGMENT -> desyncFragmentLabel
        DesyncMode.SPLIT -> desyncSplitLabel
    }

    fun desyncModeSummary(mode: DesyncMode): String = when (mode) {
        DesyncMode.COMBO -> desyncComboSummary
        DesyncMode.TLS_RECORD -> desyncTlsRecordSummary
        DesyncMode.FRAGMENT -> desyncFragmentSummary
        DesyncMode.SPLIT -> desyncSplitSummary
    }

    fun splitTunnelModeLabel(mode: SplitTunnelMode): String = when (mode) {
        SplitTunnelMode.BYPASS_SELECTED -> splitModeBypassSelected
        SplitTunnelMode.ONLY_SELECTED -> splitModeOnlySelected
    }

    fun themeLabel(theme: ThemePreference): String = when (theme) {
        ThemePreference.SYSTEM -> themeSystem
        ThemePreference.DARK -> themeDark
        ThemePreference.LIGHT -> themeLight
    }

    fun languageOptionLabel(language: AppLanguage): String = when (language) {
        AppLanguage.SYSTEM -> languageSystem
        AppLanguage.EN -> languageEnglish
        AppLanguage.TR -> languageTurkish
    }

    fun stageLabel(rawStageLabel: String): String = when (rawStageLabel) {
        "ComboMultiRecord" -> stageCombo
        "OobSniDesync" -> stageOobSni
        "MultiRecordOob" -> stageMultiOob
        "FineFragment" -> stageFineFragment
        "DeepRecordStorm" -> stageDeepStorm
        "SlowSniSlice" -> stageSlowSni
        "DirectPassthrough" -> stagePassthrough
        else -> rawStageLabel
    }

    fun stageShort(stageNumber: Int, rawStageLabel: String): String =
        "$stageWord $stageNumber \u00B7 ${stageLabel(rawStageLabel)}"

    fun tileStage(stageNumber: Int): String =
        "$stageWord ${stageNumber.coerceAtLeast(1)}"

    fun notificationConnectedSubtitle(stageNumber: Int, rxText: String, txText: String): String =
        "$stageWord ${stageNumber.coerceAtLeast(1)} \u00B7 \u2193 $rxText  \u2191 $txText"

    fun localizeChangeSummary(rawSummary: String): String {
        if (rawSummary.isBlank()) return ""
        return rawSummary
            .split(',')
            .mapNotNull { token ->
                val trimmed = token.trim()
                if (trimmed.isEmpty()) return@mapNotNull null
                when (trimmed) {
                    "Mode" -> changeKeyMode
                    "Chunk" -> changeKeyChunk
                    "DNS" -> changeKeyDns
                    "DoH" -> changeKeyDoh
                    "IPv4" -> changeKeyIpv4
                    "QUIC" -> changeKeyQuic
                    "Bypass" -> changeKeyBypass
                    "Apps" -> changeKeyApps
                    else -> trimmed
                }
            }
            .joinToString(", ")
    }

    fun reconnectToApplyWithSummary(rawSummary: String): String {
        val localized = localizeChangeSummary(rawSummary)
        return if (localized.isNotBlank()) {
            "$reconnectToApplyPrefix \u00B7 $localized"
        } else {
            reconnectToApply
        }
    }

    fun filterSelectedCount(count: Int): String = "$filterSelected ($count)"

    fun splitBypassedCount(count: Int): String = "$count $splitBypassedSuffix"

    fun splitRoutedCount(count: Int): String = "$count $splitRoutedSuffix"

    fun updateVersionOnGitHub(versionTag: String): String =
        if (isTurkish) "GitHub'da $versionTag" else "$versionTag on GitHub"

    fun updateAvailableWithTag(versionTag: String): String =
        "$updateAvailableTitle \u00B7 $versionTag"

    fun updateVersionAvailable(version: String): String {
        val tag = if (version.startsWith("v", ignoreCase = true)) version else "v$version"
        return if (isTurkish) "$tag sürümü mevcut" else "Update $tag available"
    }

    fun cdLiveThroughput(rateLabel: String): String = "$cdLiveThroughputPrefix $rateLabel"

    fun diagnosticsAllPassed(total: Int): String =
        if (isTurkish) "$total kontrolün tamamı geçti" else "All $total checks passed"

    fun diagnosticsPartialPassed(passedCount: Int, total: Int): String =
        if (isTurkish) "$total kontrolden $passedCount geçti" else "$passedCount of $total passed"

    fun diagnosticsIssuesDetected(failedCount: Int): String =
        if (isTurkish) {
            "$failedCount sorun algılandı - DNS veya ağ ayarlarını kontrol edin"
        } else {
            val noun = if (failedCount == 1) "issue" else "issues"
            "$failedCount $noun detected - check DNS or network settings"
        }

    fun errorDuplicateDomain(domain: String): String =
        if (isTurkish) "$domain zaten istisna listesinde" else "$domain is already in the bypass list"

    fun cdRemoveDomain(domain: String): String =
        if (isTurkish) "$domain kaldır" else "Remove $domain"

    fun clearedSelectedApps(count: Int): String =
        if (isTurkish) {
            "$count seçili uygulama temizlendi"
        } else {
            val noun = if (count == 1) "app" else "apps"
            "Cleared $count selected $noun"
        }

    fun dnsUpdatedTo(displayAddr: String): String =
        if (isTurkish) "DNS güncellendi: $displayAddr" else "DNS updated to $displayAddr"

    fun addedBypassDomain(domain: String): String =
        if (isTurkish) "$domain istisna listesine eklendi" else "Added $domain to bypass list"

    fun removedBypassDomain(domain: String): String =
        if (isTurkish) "$domain kaldırıldı" else "Removed $domain"

    fun importFailed(reason: String): String =
        if (isTurkish) "İçe aktarma başarısız: $reason" else "Import failed: $reason"

    companion object {
        fun resolve(
            language: AppLanguage,
            systemLocale: Locale = Locale.getDefault(),
        ): VdpiStrings = when (language) {
            AppLanguage.EN -> EnglishStrings
            AppLanguage.TR -> TurkishStrings
            AppLanguage.SYSTEM -> {
                val lang = systemLocale.language.lowercase(Locale.ROOT)
                if (lang == "tr") TurkishStrings else EnglishStrings
            }
        }

        fun forLanguage(
            language: AppLanguage,
            systemLocale: Locale = Locale.getDefault(),
        ): VdpiStrings = resolve(language, systemLocale)
    }
}

val EnglishStrings = VdpiStrings(
    languageCode = "en",

    tabTunnel = "Tunnel",
    tabApps = "Apps",
    tabSettings = "Settings",

    actionConnect = "Connect",
    actionDisconnect = "Disconnect",
    actionReconnect = "Reconnect",
    actionDone = "Done",
    actionDismiss = "Dismiss",
    actionUndo = "Undo",
    actionApply = "Apply",
    actionAdd = "Add",
    actionOpen = "Open",
    actionDownload = "Download",
    actionCopy = "Copy",
    actionCopied = "Copied",
    actionRerun = "Re-run",
    actionClearSearch = "Clear Search",
    valueEnabled = "Enabled",
    valueOff = "Off",
    valueAllowed = "Allowed",
    valueAllApps = "All Apps",
    customDohLabel = "custom DoH",

    statusConnected = "Connected",
    statusConnecting = "Connecting",
    statusConnectingEllipsis = "Connecting...",
    statusNotConnected = "Not Connected",
    statusDisconnected = "Disconnected",
    statusConnectionError = "Connection Error",
    statusTunnelError = "Tunnel Error",
    statusPassed = "Passed",
    statusFailed = "Failed",
    heroEstablishingTunnel = "Establishing local tunnel...",
    heroTunnelReady = "Local anti-DPI tunnel ready",
    heroTunnelStoppedUnexpectedly = "Tunnel stopped unexpectedly",

    reconnectSettingsChanged = "Settings Changed",
    reconnectToApply = "Reconnect to apply",
    reconnectToApplyPrefix = "Reconnect to apply",
    accessoryEstablishingTunnel = "Establishing tunnel",
    accessoryConnectionInterrupted = "Connection interrupted",
    accessoryTapToOpen = "Tap to open tunnel",
    cdReconnectTunnel = "Reconnect tunnel",
    cdDisconnectTunnel = "Disconnect tunnel",
    changeKeyMode = "Mode",
    changeKeyChunk = "Chunk",
    changeKeyDns = "DNS",
    changeKeyDoh = "DoH",
    changeKeyIpv4 = "IPv4",
    changeKeyQuic = "QUIC",
    changeKeyBypass = "Bypass",
    changeKeyApps = "Apps",

    sectionConnection = "Connection",
    sectionProfile = "Profile",
    metricDownload = "Download",
    metricUpload = "Upload",
    metricUptime = "Uptime",
    metricActivity = "Activity",
    metricStrategy = "Strategy",
    metricMode = "Mode",
    metricDns = "DNS",
    metricQuicBlocked = "QUIC Blocked",
    metricQuicBlocking = "QUIC Blocking",
    metricDroppedPackets = "Dropped Packets",
    metricSplitTunnel = "Split Tunnel",
    cdLiveThroughputPrefix = "Live throughput",
    splitNoneProtected = "0 apps (none protected)",
    splitBypassedSuffix = "Bypassed",
    splitRoutedSuffix = "Routed",

    stageWord = "Stage",
    stageCombo = "Combo",
    stageOobSni = "OOB SNI",
    stageMultiOob = "Multi + OOB",
    stageFineFragment = "Fine Fragment",
    stageDeepStorm = "Deep Storm",
    stageSlowSni = "Slow SNI",
    stagePassthrough = "Passthrough",

    diagnosticsTitle = "Diagnostics",
    diagnosticsChecksHeader = "Checks",
    diagnosticsRunning = "Verifying DNS, DoH, and TLS connectivity...",
    diagnosticsEmptyReturned = "No diagnostic checks were returned. Tap Re-run to try again.",
    diagnosticsTapToRun = "Tap Re-run to verify DNS, DoH, and TLS endpoints.",
    diagnosticsShareSubject = "vdpi Diagnostics Report",
    diagnosticsShareChooser = "Share Diagnostics",
    cdShareDiagnostics = "Share diagnostics report",
    logsTitle = "Engine Logs",
    logsEmptyTitle = "No Engine Logs Yet",
    logsEmptySubtitle = "Connect the tunnel to record activity.",
    logsClipboardLabel = "vdpi engine logs",

    appsTitle = "Apps",
    splitModeBypassSelected = "Bypass Selected",
    splitModeOnlySelected = "Only Selected",
    appsBypassSelectedFooter = "Selected apps connect directly without DPI bypass.",
    appsOnlySelectedFooter = "Only selected apps route through vdpi.",
    cdResetSelectedApps = "Reset selected apps",
    filterAll = "All",
    filterSelected = "Selected",
    filterSystem = "System",
    badgeSystem = "System",
    appsLoading = "Loading installed apps",
    appsEmptySelectedTitle = "No Apps Selected",
    appsEmptySearchTitle = "No Matching Apps",
    appsEmptyAllTitle = "No Apps Available",
    appsEmptySelectedSubtitle = "Switch to All and toggle any app to include it.",
    appsEmptySearchSubtitle = "Try another app name or package identifier.",
    appsEmptyAllSubtitle = "Enable System to inspect system packages.",
    appsSearchPlaceholder = "Search apps",
    cdClearSearch = "Clear search",

    settingsTitle = "Settings",
    sectionDesyncEngine = "Desync Engine",
    desyncComboLabel = "Combo",
    desyncComboSummary = "4-record TLS split + adaptive 7-stage auto-heal",
    desyncTlsRecordLabel = "TLS Record",
    desyncTlsRecordSummary = "Split ClientHello across two RFC TLS records",
    desyncFragmentLabel = "Fragment",
    desyncFragmentSummary = "Single outer TLS record sliced at SNI boundaries",
    desyncSplitLabel = "Split",
    desyncSplitSummary = "Initial chunk-byte TCP split on first flight",
    labelChunkSize = "Chunk Size",
    cdDecreaseChunkSize = "Decrease chunk size",
    cdIncreaseChunkSize = "Increase chunk size",
    footerDesyncEngine = "Splits initial TLS ClientHello packets to evade DPI inspection. Chunk size sets the first fragment length (1-64 bytes).",

    sectionDnsPrivacy = "DNS & Privacy",
    placeholderCustomDns = "Custom DNS (IP or https://...)",
    errorInvalidDns = "Enter a valid IPv4, IPv6, or https:// DoH URL",
    labelDoh = "DNS over HTTPS",
    subtitleDohRequired = "Required for HTTPS DoH URL",
    subtitleDohDefault = "Encrypt DNS queries with automatic failover",
    labelBlockQuic = "Block QUIC",
    subtitleBlockQuic = "Drop UDP/443 so apps fall back to TCP TLS",
    labelIpv4Only = "IPv4 Only",
    subtitleIpv4Only = "Skip AAAA lookups and IPv6 tunnel routes",
    footerDnsPrivacy = "Blocking QUIC forces HTTP/3 traffic onto TCP where DPI desync applies.",

    sectionBypassDomains = "Bypass Domains",
    placeholderAddDomain = "Add domain (e.g. example.com)",
    errorInvalidDomain = "Enter a valid domain (e.g. example.com or *.example.com)",
    footerBypassDomains = "Matching domains and subdomains connect directly without DPI desync. Local networks are bypassed automatically.",

    sectionAppearance = "Appearance",
    themeSystem = "System",
    themeDark = "Dark",
    themeLight = "Light",

    sectionLanguage = "Language",
    languageSystem = "System",
    languageEnglish = "English",
    languageTurkish = "Türkçe",

    sectionSystem = "System",
    labelClearCache = "Clear Engine Cache",
    subtitleClearCache = "Reset learned TLS stages and DNS entries",
    labelSystemVpn = "System VPN Settings",
    subtitleSystemVpn = "Configure Always-on VPN in Android settings",

    sectionBackupRestore = "Backup & Restore",
    labelExportSettings = "Export Settings",
    subtitleExportSettings = "Save configuration as JSON",
    labelImportSettings = "Import Settings",
    subtitleImportSettings = "Restore configuration from JSON",
    footerBackupRestore = "Exports desync, DNS, bypass domains, split tunnel, theme, and language preferences.",

    sectionUpdates = "Updates",
    updateAvailable = "Update available",
    updateAvailableTitle = "Update Available",
    subtitleOpenRelease = "Open release on GitHub",
    labelCheckForUpdates = "Check for Updates",
    updateUpToDate = "Up to date",
    updateCheckFailed = "Unable to check for updates",
    cdDismissUpdate = "Dismiss update notice",

    sectionAbout = "About",
    labelGitHubRepo = "GitHub Repository",

    feedbackVpnPermissionDenied = "VPN permission was denied",
    feedbackVpnPermissionRequired = "VPN permission required",
    feedbackExportSerializeFailed = "Failed to serialize settings",
    feedbackSettingsExported = "Settings exported",
    feedbackSettingsExportFailed = "Failed to export settings",
    feedbackImportFileTooLarge = "Settings file too large (max 256 KB)",
    feedbackImportReadFailed = "Could not read settings file",
    feedbackImportFileEmpty = "Settings file is empty",
    feedbackFilePickerUnavailable = "File picker unavailable",
    feedbackSystemVpnUnavailable = "System VPN settings unavailable on this device",
    feedbackCacheCleared = "Adaptive cache cleared",
    feedbackCacheClearFailed = "Failed to clear adaptive cache",
    importInvalidJson = "Invalid settings JSON",
    importSuccess = "Settings imported",
    importSuccessReconnect = "Settings imported \u00B7 reconnect to apply",

    notificationChannelName = "Tunnel Status",
    notificationChannelDesc = "Shows tunnel status while vdpi is connected",
    notificationActionDisconnect = "Disconnect",
    notificationActionReconnect = "Reconnect",
    notificationTitleConnected = "vdpi Connected",
    notificationTitleConnecting = "Connecting to vdpi",
    notificationSubtitleConnecting = "Starting local tunnel",
    notificationPermissionHint = "Allow notifications to keep vdpi visible while connected",
    notificationSettingsAction = "Settings",
    errorBackgroundStartBlocked = "Background start blocked by system",
    errorNativeEngineLoadFailed = "Failed to load native engine",
    errorVpnInterfaceFailed = "VPN permission revoked or interface could not be created",
    errorEngineStartFailed = "Engine failed to start",
    errorEngineExitedImmediately = "Engine exited immediately after start",
    errorVpnBackgroundStart = "Unable to start VPN service in background",
    errorVpnReconnect = "Unable to reconnect VPN service",
    tileStarting = "Starting",
    tileOff = "Off",
    widgetStatusConnected = "Protected",
    widgetStatusConnecting = "Connecting...",
    widgetStatusOff = "Off",
    widgetStatusError = "Needs attention",
    widgetActionConnect = "Connect",
    widgetActionDisconnect = "Disconnect",
)

val TurkishStrings = VdpiStrings(
    languageCode = "tr",

    tabTunnel = "Tünel",
    tabApps = "Uygulamalar",
    tabSettings = "Ayarlar",

    actionConnect = "Bağlan",
    actionDisconnect = "Bağlantıyı Kes",
    actionReconnect = "Yeniden Bağlan",
    actionDone = "Bitti",
    actionDismiss = "Kapat",
    actionUndo = "Geri Al",
    actionApply = "Uygula",
    actionAdd = "Ekle",
    actionOpen = "Aç",
    actionDownload = "İndir",
    actionCopy = "Kopyala",
    actionCopied = "Kopyalandı",
    actionRerun = "Tekrarla",
    actionClearSearch = "Aramayı Temizle",
    valueEnabled = "Açık",
    valueOff = "Kapalı",
    valueAllowed = "İzinli",
    valueAllApps = "Tüm Uygulamalar",
    customDohLabel = "özel DoH",

    statusConnected = "Bağlı",
    statusConnecting = "Bağlanıyor",
    statusConnectingEllipsis = "Bağlanıyor...",
    statusNotConnected = "Bağlı Değil",
    statusDisconnected = "Bağlantı Kesildi",
    statusConnectionError = "Bağlantı Hatası",
    statusTunnelError = "Tünel Hatası",
    statusPassed = "Geçti",
    statusFailed = "Başarısız",
    heroEstablishingTunnel = "Yerel tünel kuruluyor...",
    heroTunnelReady = "Yerel anti-DPI tüneli hazır",
    heroTunnelStoppedUnexpectedly = "Tünel beklenmedik şekilde durdu",

    reconnectSettingsChanged = "Ayarlar Değişti",
    reconnectToApply = "Uygulamak için yeniden bağlanın",
    reconnectToApplyPrefix = "Yeniden bağlanın",
    accessoryEstablishingTunnel = "Tünel kuruluyor",
    accessoryConnectionInterrupted = "Bağlantı kesildi",
    accessoryTapToOpen = "Tüneli açmak için dokunun",
    cdReconnectTunnel = "Tüneli yeniden bağla",
    cdDisconnectTunnel = "Tünel bağlantısını kes",
    changeKeyMode = "Mod",
    changeKeyChunk = "Parça",
    changeKeyDns = "DNS",
    changeKeyDoh = "DoH",
    changeKeyIpv4 = "IPv4",
    changeKeyQuic = "QUIC",
    changeKeyBypass = "İstisna",
    changeKeyApps = "Uygulamalar",

    sectionConnection = "Bağlantı",
    sectionProfile = "Profil",
    metricDownload = "İndirme",
    metricUpload = "Yükleme",
    metricUptime = "Çalışma Süresi",
    metricActivity = "Etkinlik",
    metricStrategy = "Strateji",
    metricMode = "Mod",
    metricDns = "DNS",
    metricQuicBlocked = "Engellenen QUIC",
    metricQuicBlocking = "QUIC Engelleme",
    metricDroppedPackets = "Düşen Paketler",
    metricSplitTunnel = "Bölünmüş Tünel",
    cdLiveThroughputPrefix = "Anlık hız",
    splitNoneProtected = "0 uygulama (korumasız)",
    splitBypassedSuffix = "Hariç",
    splitRoutedSuffix = "Tünelde",

    stageWord = "Aşama",
    stageCombo = "Kombo",
    stageOobSni = "OOB SNI",
    stageMultiOob = "Çoklu + OOB",
    stageFineFragment = "İnce Parça",
    stageDeepStorm = "Derin Fırtına",
    stageSlowSni = "Yavaş SNI",
    stagePassthrough = "Doğrudan",

    diagnosticsTitle = "Tanılama",
    diagnosticsChecksHeader = "Kontroller",
    diagnosticsRunning = "DNS, DoH ve TLS bağlantısı doğrulanıyor...",
    diagnosticsEmptyReturned = "Tanılama sonucu alınamadı. Yeniden denemek için Tekrarla'ya dokunun.",
    diagnosticsTapToRun = "DNS, DoH ve TLS uç noktalarını doğrulamak için Tekrarla'ya dokunun.",
    diagnosticsShareSubject = "vdpi Tanılama Raporu",
    diagnosticsShareChooser = "Tanılamayı Paylaş",
    cdShareDiagnostics = "Tanılama raporunu paylaş",
    logsTitle = "Motor Günlüğü",
    logsEmptyTitle = "Henüz Motor Günlüğü Yok",
    logsEmptySubtitle = "Etkinliği kaydetmek için tüneli bağlayın.",
    logsClipboardLabel = "vdpi motor günlüğü",

    appsTitle = "Uygulamalar",
    splitModeBypassSelected = "Seçilileri Atla",
    splitModeOnlySelected = "Sadece Seçililer",
    appsBypassSelectedFooter = "Seçili uygulamalar DPI aşımı olmadan doğrudan bağlanır.",
    appsOnlySelectedFooter = "Yalnızca seçili uygulamalar vdpi üzerinden yönlendirilir.",
    cdResetSelectedApps = "Seçili uygulamaları sıfırla",
    filterAll = "Tümü",
    filterSelected = "Seçili",
    filterSystem = "Sistem",
    badgeSystem = "Sistem",
    appsLoading = "Yüklü uygulamalar yükleniyor",
    appsEmptySelectedTitle = "Seçili Uygulama Yok",
    appsEmptySearchTitle = "Eşleşen Uygulama Yok",
    appsEmptyAllTitle = "Uygulama Bulunamadı",
    appsEmptySelectedSubtitle = "Eklemek için Tümü sekmesine geçip bir uygulamayı seçin.",
    appsEmptySearchSubtitle = "Başka bir uygulama adı veya paket adı deneyin.",
    appsEmptyAllSubtitle = "Sistem paketlerini görmek için Sistem filtresini açın.",
    appsSearchPlaceholder = "Uygulama ara",
    cdClearSearch = "Aramayı temizle",

    settingsTitle = "Ayarlar",
    sectionDesyncEngine = "Desync Motoru",
    desyncComboLabel = "Kombo",
    desyncComboSummary = "4 kayıtlı TLS bölme + 7 aşamalı otomatik onarım",
    desyncTlsRecordLabel = "TLS Kaydı",
    desyncTlsRecordSummary = "ClientHello paketini iki RFC TLS kaydına böler",
    desyncFragmentLabel = "Parçalama",
    desyncFragmentSummary = "Tek dış TLS kaydını SNI sınırlarından dilimler",
    desyncSplitLabel = "TCP Bölme",
    desyncSplitSummary = "İlk pakette bayt düzeyinde TCP bölme uygular",
    labelChunkSize = "Parça Boyutu",
    cdDecreaseChunkSize = "Parça boyutunu azalt",
    cdIncreaseChunkSize = "Parça boyutunu artır",
    footerDesyncEngine = "DPI denetimini aşmak için ilk TLS ClientHello paketlerini böler. Parça boyutu ilk dilim uzunluğunu belirler (1-64 bayt).",

    sectionDnsPrivacy = "DNS ve Gizlilik",
    placeholderCustomDns = "Özel DNS (IP veya https://...)",
    errorInvalidDns = "Geçerli bir IPv4, IPv6 veya https:// DoH adresi girin",
    labelDoh = "DNS over HTTPS",
    subtitleDohRequired = "HTTPS DoH adresi için zorunlu",
    subtitleDohDefault = "DNS sorgularını otomatik yedeklemeyle şifreler",
    labelBlockQuic = "QUIC Engelle",
    subtitleBlockQuic = "Uygulamaların TCP TLS'e geçmesi için UDP/443 trafiğini keser",
    labelIpv4Only = "Yalnızca IPv4",
    subtitleIpv4Only = "AAAA sorgularını ve IPv6 tünel rotalarını atlar",
    footerDnsPrivacy = "QUIC engelleme, HTTP/3 trafiğini DPI desync uygulanan TCP'ye yönlendirir.",

    sectionBypassDomains = "Hariç Tutulan Alan Adları",
    placeholderAddDomain = "Alan adı ekle (örn. example.com)",
    errorInvalidDomain = "Geçerli bir alan adı girin (örn. example.com veya *.example.com)",
    footerBypassDomains = "Eşleşen alan adları ve alt alan adları DPI desync olmadan doğrudan bağlanır. Yerel ağlar otomatik olarak hariç tutulur.",

    sectionAppearance = "Görünüm",
    themeSystem = "Sistem",
    themeDark = "Koyu",
    themeLight = "Açık",

    sectionLanguage = "Dil",
    languageSystem = "Sistem",
    languageEnglish = "English",
    languageTurkish = "Türkçe",

    sectionSystem = "Sistem",
    labelClearCache = "Motor Önbelleğini Temizle",
    subtitleClearCache = "Öğrenilen TLS aşamalarını ve DNS kayıtlarını sıfırlar",
    labelSystemVpn = "Sistem VPN Ayarları",
    subtitleSystemVpn = "Android ayarlarında Her Zaman Açık VPN'i yapılandırın",

    sectionBackupRestore = "Yedekleme ve Geri Yükleme",
    labelExportSettings = "Ayarları Dışa Aktar",
    subtitleExportSettings = "Yapılandırmayı JSON olarak kaydet",
    labelImportSettings = "Ayarları İçe Aktar",
    subtitleImportSettings = "Yapılandırmayı JSON dosyasından geri yükle",
    footerBackupRestore = "Desync, DNS, istisna alan adları, bölünmüş tünel, tema ve dil tercihlerini dışa aktarır.",

    sectionUpdates = "Güncellemeler",
    updateAvailable = "Güncelleme mevcut",
    updateAvailableTitle = "Güncelleme Mevcut",
    subtitleOpenRelease = "Sürümü GitHub'da aç",
    labelCheckForUpdates = "Güncellemeleri Denetle",
    updateUpToDate = "Güncel",
    updateCheckFailed = "Güncellemeler denetlenemedi",
    cdDismissUpdate = "Güncelleme bildirimini kapat",

    sectionAbout = "Hakkında",
    labelGitHubRepo = "GitHub Deposu",

    feedbackVpnPermissionDenied = "VPN izni reddedildi",
    feedbackVpnPermissionRequired = "VPN izni gerekli",
    feedbackExportSerializeFailed = "Ayarlar serileştirilemedi",
    feedbackSettingsExported = "Ayarlar dışa aktarıldı",
    feedbackSettingsExportFailed = "Ayarlar dışa aktarılamadı",
    feedbackImportFileTooLarge = "Ayar dosyası çok büyük (en fazla 256 KB)",
    feedbackImportReadFailed = "Ayar dosyası okunamadı",
    feedbackImportFileEmpty = "Ayar dosyası boş",
    feedbackFilePickerUnavailable = "Dosya seçici kullanılamıyor",
    feedbackSystemVpnUnavailable = "Bu cihazda sistem VPN ayarları kullanılamıyor",
    feedbackCacheCleared = "Uyarlamalı önbellek temizlendi",
    feedbackCacheClearFailed = "Uyarlamalı önbellek temizlenemedi",
    importInvalidJson = "Geçersiz ayar JSON dosyası",
    importSuccess = "Ayarlar içe aktarıldı",
    importSuccessReconnect = "Ayarlar içe aktarıldı \u00B7 uygulamak için yeniden bağlanın",

    notificationChannelName = "Tünel Durumu",
    notificationChannelDesc = "vdpi bağlıyken tünel durumunu gösterir",
    notificationActionDisconnect = "Bağlantıyı Kes",
    notificationActionReconnect = "Yeniden Bağlan",
    notificationTitleConnected = "vdpi Bağlı",
    notificationTitleConnecting = "vdpi Bağlanıyor",
    notificationSubtitleConnecting = "Yerel tünel başlatılıyor",
    notificationPermissionHint = "Bağlıyken vdpi durumunu görmek için bildirimlere izin verin",
    notificationSettingsAction = "Ayarlar",
    errorBackgroundStartBlocked = "Arka plan başlatma sistem tarafından engellendi",
    errorNativeEngineLoadFailed = "Yerel motor yüklenemedi",
    errorVpnInterfaceFailed = "VPN izni iptal edildi veya arayüz oluşturulamadı",
    errorEngineStartFailed = "Motor başlatılamadı",
    errorEngineExitedImmediately = "Motor başlatıldıktan hemen sonra kapandı",
    errorVpnBackgroundStart = "VPN servisi arka planda başlatılamadı",
    errorVpnReconnect = "VPN servisi yeniden bağlanamadı",
    tileStarting = "Başlatılıyor",
    tileOff = "Kapalı",
    widgetStatusConnected = "Korunuyor",
    widgetStatusConnecting = "Bağlanıyor...",
    widgetStatusOff = "Kapalı",
    widgetStatusError = "Dikkat gerekiyor",
    widgetActionConnect = "Bağlan",
    widgetActionDisconnect = "Kes",
)

val LocalVdpiStrings = staticCompositionLocalOf { EnglishStrings }
