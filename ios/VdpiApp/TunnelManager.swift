import Foundation
import NetworkExtension
import SwiftUI
import UIKit

public enum TunnelPhase: Equatable, Sendable {
    case disconnected
    case connecting
    case connected
    case disconnecting
    case error

    public var label: String {
        label(in: .en)
    }

    public func label(in language: AppLanguage) -> String {
        let l10n = L10n.catalog(for: language)
        switch self {
        case .disconnected: return l10n.phaseStandby
        case .connecting: return l10n.phaseConnecting
        case .connected: return l10n.phaseProtected
        case .disconnecting: return l10n.phaseStopping
        case .error: return l10n.phaseError
        }
    }
}

public struct DoctorUiState: Equatable, Sendable {
    public var running: Bool
    public var report: DoctorReport?
    public var error: String?

    public init(
        running: Bool = false,
        report: DoctorReport? = nil,
        error: String? = nil
    ) {
        self.running = running
        self.report = report
        self.error = error
    }
}

public enum SettingsImportError: LocalizedError, Equatable, Sendable {
    case emptyPayload
    case invalidJSON
    case unrecognizedFormat
    case invalidDnsAddress(String)

    public func localizedMessage(in language: AppLanguage) -> String {
        let l10n = L10n.catalog(for: language)
        switch self {
        case .emptyPayload:
            return l10n.importErrorEmptyPayload
        case .invalidJSON:
            return l10n.importErrorInvalidJson
        case .unrecognizedFormat:
            return l10n.importErrorUnrecognizedFormat
        case .invalidDnsAddress(let addr):
            return l10n.importErrorInvalidDns(addr)
        }
    }

    public var errorDescription: String? {
        localizedMessage(in: VdpiAppGroup.loadSettings().language)
    }
}

@MainActor
public final class TunnelManager: ObservableObject {
    @Published var settings: VdpiSettings
    @Published var phase: TunnelPhase = .disconnected
    @Published var errorMessage: String? = nil
    @Published var telemetry: TelemetrySnapshot = .idle
    @Published var doctorState: DoctorUiState = DoctorUiState()
    @Published var pendingReconnect: Bool = false
    @Published var reconnectPopupVisible: Bool = false
    @Published var pendingChangeSummary: String = ""
    @Published private(set) var isReloading: Bool = false
    @Published var toastMessage: String? = nil

    @Published public private(set) var appliedConfig: NativeEngineConfig? = nil
    @Published public private(set) var throughputSamples: [UInt64] = []
    @Published public private(set) var currentRateBytesPerSec: UInt64 = 0
    @Published public private(set) var availableUpdate: VdpiUpdateInfo? = nil
    @Published public private(set) var isCheckingUpdate: Bool = false
    @Published public private(set) var updateStatusMessage: String? = nil

    let engineVersion: String

    public var appVersion: String {
        if let raw = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String {
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty {
                return trimmed
            }
        }
        return "0.6.1"
    }

    private static let providerConfigSettingsKey = "vdpiSettingsJSON"
    private static let maxThroughputSamples = 24
    private static let updateCheckCooldownSeconds: TimeInterval = 6 * 60 * 60
    private static let lastUpdateCheckTimestampKey = "vdpi_last_update_check_ts_v1"
    private static let dismissedUpdateVersionKey = "vdpi_dismissed_update_version_v1"
    private nonisolated static let validSettingsKeys: Set<String> = [
        "desyncMode",
        "chunkSize",
        "dnsAddr",
        "enableDoh",
        "ipv4Only",
        "blockQuic",
        "mtu",
        "bypassDomains",
        "onDemandEnabled",
        "theme",
        "language",
    ]

    private enum UpdateStatusKind: Equatable {
        case failed
        case upToDate
        case available(String)
    }

    private var l10n: L10n.Catalog {
        L10n.catalog(for: settings.language)
    }

    private var vpnManager: NETunnelProviderManager?
    private nonisolated(unsafe) var statusObserver: NSObjectProtocol?
    private var loadTask: Task<Void, Never>?
    private var lifecycleTask: Task<Void, Never>?
    private var reloadTask: Task<Void, Never>?
    private var onDemandSyncTask: Task<Void, Never>?
    private var clearCacheTask: Task<Void, Never>?
    private var doctorTask: Task<Void, Never>?
    private var telemetryTask: Task<Void, Never>?
    private var toastTask: Task<Void, Never>?
    private var updateCheckTask: Task<Void, Never>?
    private var isManualUpdateCheck: Bool = false
    private var lastUpdateStatusKind: UpdateStatusKind? = nil
    private var lastThroughputTotalBytes: UInt64?
    private var lastThroughputUptimeNs: UInt64?
    private var reloadGeneration: UInt64 = 0
    private var lifecycleGeneration: UInt64 = 0
    private var disconnectErrorGeneration: UInt64 = 0
    private var toastGeneration: UInt64 = 0
    private var isSceneActive: Bool = true
    private var userInitiatedDisconnect: Bool = false
    private var engineUnhealthyWhileConnected: Bool = false
    private var consecutiveUnhealthySamples: Int = 0

    public init() {
        let loaded = VdpiAppGroup.loadSettings()
        self.settings = loaded
        self.appliedConfig = VdpiAppGroup.loadAppliedConfig()
        self.engineVersion = VdpiNativeBridge.version()
        observeVpnStatus()
        loadTask = Task { [weak self] in
            await self?.loadOrCreateManager()
        }
        checkForUpdates(manual: false)
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        loadTask?.cancel()
        lifecycleTask?.cancel()
        reloadTask?.cancel()
        onDemandSyncTask?.cancel()
        clearCacheTask?.cancel()
        doctorTask?.cancel()
        telemetryTask?.cancel()
        toastTask?.cancel()
        updateCheckTask?.cancel()
    }

    func setSceneActive(_ active: Bool) {
        isSceneActive = active
        if active {
            if let status = vpnManager?.connection.status,
               lifecycleTask == nil || status == .connected
            {
                if status == .connected && engineUnhealthyWhileConnected && phase == .error {
                    return
                }
                syncStatus(status)
            } else if phase == .connected {
                startTelemetryPolling()
            }
        } else {
            telemetryTask?.cancel()
            telemetryTask = nil
            lastThroughputTotalBytes = nil
            lastThroughputUptimeNs = nil
        }
    }

    func updateSettings(_ mutate: (inout VdpiSettings) -> Void) {
        let previous = settings
        var next = previous
        mutate(&next)
        guard next != previous else { return }

        let onDemandChanged = next.onDemandEnabled != previous.onDemandEnabled
        let languageChanged = next.language != previous.language
        let nativeConfigChanged = next.requiresTunnelReload(comparedTo: previous)

        // Ensure an active or connecting tunnel always has a baseline config before
        // applying the mutation so unapplied edits are never missed.
        if (phase == .connected || phase == .connecting), appliedConfig == nil {
            appliedConfig = VdpiAppGroup.loadAppliedConfig() ?? previous.toNativeConfig()
        }

        settings = next
        VdpiAppGroup.saveSettings(next)

        if nativeConfigChanged {
            recomputePendingReconnect(revealPopup: true)
        } else if languageChanged && pendingReconnect {
            recomputePendingReconnect(revealPopup: false)
        }

        if languageChanged {
            refreshLocalizedUpdateStatusMessage()
        }

        if onDemandChanged {
            onDemandSyncTask?.cancel()
            onDemandSyncTask = Task { [weak self] in
                await self?.syncOnDemandPreference()
            }
        }
    }

    private func refreshLocalizedUpdateStatusMessage() {
        guard let kind = lastUpdateStatusKind else { return }
        switch kind {
        case .failed:
            updateStatusMessage = l10n.updateCheckFailed
        case .upToDate:
            updateStatusMessage = l10n.updateUpToDate
        case .available(let version):
            updateStatusMessage = l10n.updateAvailableInline(version: version)
        }
    }

    func dismissReconnectPopup() {
        if reconnectPopupVisible {
            reconnectPopupVisible = false
        }
    }

    func resetSettings() {
        let defaults = VdpiSettings(theme: settings.theme, language: settings.language)
        updateSettings { $0 = defaults }
        showToast(l10n.toastSettingsReset)
    }

    func toggleTunnel() {
        switch phase {
        case .connected, .connecting:
            disconnect()
        case .disconnected, .error:
            connect()
        case .disconnecting:
            break
        }
    }

    func connect() {
        reloadGeneration &+= 1
        reloadTask?.cancel()
        reloadTask = nil
        if isReloading {
            isReloading = false
        }

        onDemandSyncTask?.cancel()
        onDemandSyncTask = nil

        let needsRestartFromUnhealthy = engineUnhealthyWhileConnected
        engineUnhealthyWhileConnected = false

        lifecycleGeneration &+= 1
        let generation = lifecycleGeneration
        lifecycleTask?.cancel()
        userInitiatedDisconnect = false
        disconnectErrorGeneration &+= 1
        errorMessage = nil
        phase = .connecting
        resetThroughputHistory()
        let initialTarget = settings
        VdpiAppGroup.saveSettings(initialTarget)
        appliedConfig = initialTarget.toNativeConfig()
        clearPendingReconnect()

        lifecycleTask = Task { [weak self] in
            guard let self else { return }
            defer {
                if self.lifecycleGeneration == generation {
                    self.lifecycleTask = nil
                }
            }
            await self.loadTask?.value
            guard !Task.isCancelled else { return }
            do {
                let target = self.settings
                VdpiAppGroup.saveSettings(target)
                var manager = try await self.ensureConfiguredManager(for: target)
                guard !Task.isCancelled else { return }

                if manager.connection.status == .connected {
                    if needsRestartFromUnhealthy {
                        self.userInitiatedDisconnect = true
                        if manager.isOnDemandEnabled {
                            self.applyOnDemandRules(to: manager, enabled: false)
                            try await manager.saveToPreferences()
                            guard !Task.isCancelled else { return }
                            try await manager.loadFromPreferences()
                            guard !Task.isCancelled else { return }
                        }
                        manager.connection.stopVPNTunnel()
                        let disconnected = await self.waitForLifecycleDisconnect(
                            manager: manager,
                            generation: generation
                        )
                        self.userInitiatedDisconnect = false
                        guard !Task.isCancelled, self.lifecycleGeneration == generation else { return }
                        if !disconnected {
                            throw NSError(
                                domain: "com.vulninc.vdpi.app",
                                code: 1003,
                                userInfo: [NSLocalizedDescriptionKey: self.l10n.errorPreviousTunnelStopTimeout]
                            )
                        }
                        self.phase = .connecting
                        manager = try await self.ensureConfiguredManager(for: self.settings)
                        guard !Task.isCancelled else { return }
                    } else {
                        self.syncStatus(.connected)
                        return
                    }
                }

                let launchTarget = self.settings
                VdpiAppGroup.saveSettings(launchTarget)
                if launchTarget != target {
                    manager = try await self.ensureConfiguredManager(for: launchTarget)
                    guard !Task.isCancelled else { return }
                }
                let applied = launchTarget.toNativeConfig()
                self.appliedConfig = applied
                VdpiAppGroup.saveAppliedConfig(applied)
                let startOptions: [String: NSObject]? = Self.encodeSettingsJSON(launchTarget).map {
                    [Self.providerConfigSettingsKey: $0 as NSObject]
                }
                try manager.connection.startVPNTunnel(options: startOptions)
                self.recomputePendingReconnect(revealPopup: false)
                self.triggerHaptic(.medium)
            } catch {
                guard !Task.isCancelled else { return }
                self.userInitiatedDisconnect = false
                if let neError = error as? NEVPNError,
                   neError.code == .configurationStale || neError.code == .configurationInvalid
                {
                    self.vpnManager = nil
                }
                self.phase = .error
                self.errorMessage = error.localizedDescription
                self.appliedConfig = nil
                VdpiAppGroup.saveAppliedConfig(nil)
                self.clearPendingReconnect()
                self.resetThroughputHistory()
                self.triggerNotificationHaptic(.error)
            }
        }
    }

    func disconnect() {
        reloadGeneration &+= 1
        reloadTask?.cancel()
        reloadTask = nil
        if isReloading {
            isReloading = false
        }

        onDemandSyncTask?.cancel()
        onDemandSyncTask = nil
        engineUnhealthyWhileConnected = false

        lifecycleGeneration &+= 1
        let generation = lifecycleGeneration
        lifecycleTask?.cancel()
        lifecycleTask = nil
        userInitiatedDisconnect = true
        disconnectErrorGeneration &+= 1
        errorMessage = nil
        appliedConfig = nil
        VdpiAppGroup.saveAppliedConfig(nil)
        clearPendingReconnect()

        if let manager = vpnManager {
            let initialStatus = manager.connection.status
            if initialStatus == .disconnected || initialStatus == .invalid {
                userInitiatedDisconnect = false
                phase = .disconnected
                telemetryTask?.cancel()
                telemetryTask = nil
                resetThroughputHistory()
                if manager.isOnDemandEnabled {
                    lifecycleTask = Task { [weak self] in
                        defer {
                            if let self, self.lifecycleGeneration == generation {
                                self.lifecycleTask = nil
                            }
                        }
                        self?.applyOnDemandRules(to: manager, enabled: false)
                        try? await manager.saveToPreferences()
                        guard !Task.isCancelled else { return }
                        try? await manager.loadFromPreferences()
                    }
                }
                return
            }

            phase = .disconnecting
            triggerHaptic(.light)
            lifecycleTask = Task { [weak self] in
                guard let self else { return }
                defer {
                    if self.lifecycleGeneration == generation {
                        self.lifecycleTask = nil
                    }
                }
                await self.disableOnDemandAndStop(manager: manager)
            }
            return
        }

        guard loadTask != nil else {
            userInitiatedDisconnect = false
            phase = .disconnected
            telemetryTask?.cancel()
            telemetryTask = nil
            resetThroughputHistory()
            return
        }

        if phase != .disconnected {
            phase = .disconnecting
            triggerHaptic(.light)
        }
        lifecycleTask = Task { [weak self] in
            guard let self else { return }
            defer {
                if self.lifecycleGeneration == generation {
                    self.lifecycleTask = nil
                }
            }
            await self.loadTask?.value
            guard !Task.isCancelled else { return }
            guard let manager = self.vpnManager else {
                self.userInitiatedDisconnect = false
                self.phase = .disconnected
                self.telemetryTask?.cancel()
                self.telemetryTask = nil
                self.resetThroughputHistory()
                return
            }
            await self.disableOnDemandAndStop(manager: manager)
        }
    }

    private func disableOnDemandAndStop(manager: NETunnelProviderManager) async {
        // Disable On-Demand before stopping so an explicit user disconnect is not
        // immediately overridden by NEOnDemandRuleConnect on the next packet.
        if manager.isOnDemandEnabled {
            applyOnDemandRules(to: manager, enabled: false)
            try? await manager.saveToPreferences()
            guard !Task.isCancelled else { return }
            try? await manager.loadFromPreferences()
            guard !Task.isCancelled else { return }
        }
        let currentStatus = manager.connection.status
        if currentStatus == .disconnected || currentStatus == .invalid {
            userInitiatedDisconnect = false
            phase = .disconnected
            telemetryTask?.cancel()
            telemetryTask = nil
            resetThroughputHistory()
            return
        }
        manager.connection.stopVPNTunnel()
    }

    func applyChangesLive() {
        guard !isReloading else { return }
        let target = settings
        VdpiAppGroup.saveSettings(target)

        if phase == .connected,
           vpnManager?.connection is NETunnelProviderSession
        {
            onDemandSyncTask?.cancel()
            onDemandSyncTask = nil
            reloadGeneration &+= 1
            let generation = reloadGeneration
            isReloading = true
            reloadTask?.cancel()
            reloadTask = Task { [weak self] in
                guard let self else { return }
                defer {
                    if self.reloadGeneration == generation {
                        self.isReloading = false
                        self.reloadTask = nil
                    }
                }

                if let manager = self.vpnManager {
                    let proto = self.makeTunnelProtocol(for: target)
                    manager.protocolConfiguration = proto
                    manager.localizedDescription = "vdpi"
                    manager.isEnabled = true
                    self.applyOnDemandRules(to: manager, enabled: target.onDemandEnabled)
                    try? await manager.saveToPreferences()
                    guard !Task.isCancelled, self.reloadGeneration == generation else { return }
                    try? await manager.loadFromPreferences()
                    guard !Task.isCancelled, self.reloadGeneration == generation else { return }
                }

                let replyData: Data?
                if let session = self.vpnManager?.connection as? NETunnelProviderSession {
                    if let settingsData = try? JSONEncoder().encode(target),
                       let settingsJson = String(data: settingsData, encoding: .utf8)
                    {
                        replyData = await self.sendMessage(
                            .reloadEngineWithSettings(settingsJson: settingsJson),
                            via: session
                        )
                    } else {
                        replyData = await self.sendMessage(.reloadEngine, via: session)
                    }
                } else {
                    replyData = nil
                }
                guard !Task.isCancelled, self.reloadGeneration == generation else { return }

                if let replyData,
                   let response = ProviderCommandResponse.decodeData(replyData),
                   response.ok
                {
                    let applied = target.toNativeConfig().canonicalized()
                    self.appliedConfig = applied
                    VdpiAppGroup.saveAppliedConfig(applied)
                    self.clearPendingReconnect()
                    // Re-check in case another runtime setting changed while reload was in flight.
                    if self.settings.requiresTunnelReload(comparedToApplied: applied) {
                        self.recomputePendingReconnect(revealPopup: true)
                    }
                    if self.reloadGeneration == generation {
                        self.isReloading = false
                    }
                    self.triggerNotificationHaptic(.success)
                    self.showToast(self.l10n.toastAppliedSettings)
                    await self.fetchTelemetryOnce()
                } else {
                    // Fallback to full reconnect if live reload failed.
                    guard self.phase != .disconnecting else { return }
                    if self.phase != .disconnected, let manager = self.vpnManager {
                        guard await self.stopTunnelForReconnect(manager: manager, generation: generation) else {
                            return
                        }
                    }
                    self.connect()
                }
            }
            return
        }

        if phase == .connecting, let manager = vpnManager {
            onDemandSyncTask?.cancel()
            onDemandSyncTask = nil
            lifecycleGeneration &+= 1
            lifecycleTask?.cancel()
            lifecycleTask = nil
            reloadGeneration &+= 1
            let generation = reloadGeneration
            isReloading = true
            reloadTask?.cancel()
            reloadTask = Task { [weak self] in
                guard let self else { return }
                defer {
                    if self.reloadGeneration == generation {
                        self.isReloading = false
                        self.reloadTask = nil
                    }
                }
                guard await self.stopTunnelForReconnect(manager: manager, generation: generation) else {
                    return
                }
                self.connect()
            }
            return
        }

        connect()
    }

    private func stopTunnelForReconnect(
        manager: NETunnelProviderManager,
        generation: UInt64
    ) async -> Bool {
        userInitiatedDisconnect = true
        let disabledOnDemand = manager.isOnDemandEnabled
        if disabledOnDemand {
            applyOnDemandRules(to: manager, enabled: false)
            try? await manager.saveToPreferences()
            guard !Task.isCancelled, self.reloadGeneration == generation else {
                return false
            }
            try? await manager.loadFromPreferences()
            guard !Task.isCancelled, self.reloadGeneration == generation else {
                return false
            }
        }
        manager.connection.stopVPNTunnel()
        let disconnected = await waitForDisconnect(generation: generation)
        guard !Task.isCancelled, self.reloadGeneration == generation else {
            return false
        }
        if !disconnected {
            userInitiatedDisconnect = false
            if disabledOnDemand && settings.onDemandEnabled {
                applyOnDemandRules(to: manager, enabled: true)
                try? await manager.saveToPreferences()
                try? await manager.loadFromPreferences()
            }
            syncStatus(manager.connection.status)
            showToast(l10n.toastReconnectTimedOut)
            return false
        }
        return true
    }

    private func waitForDisconnect(generation: UInt64) async -> Bool {
        let maxAttempts = 50 // 50 * 50ms = 2.5s
        for _ in 0..<maxAttempts {
            guard !Task.isCancelled, self.reloadGeneration == generation else {
                return false
            }
            let status = self.vpnManager?.connection.status ?? .disconnected
            if status == .disconnected || status == .invalid {
                return true
            }
            try? await Task.sleep(nanoseconds: 50_000_000)
        }
        guard !Task.isCancelled, self.reloadGeneration == generation else {
            return false
        }
        let finalStatus = self.vpnManager?.connection.status ?? .disconnected
        return finalStatus == .disconnected || finalStatus == .invalid
    }

    private func waitForLifecycleDisconnect(
        manager: NETunnelProviderManager,
        generation: UInt64
    ) async -> Bool {
        let maxAttempts = 50 // 50 * 50ms = 2.5s
        for _ in 0..<maxAttempts {
            guard !Task.isCancelled, self.lifecycleGeneration == generation else {
                return false
            }
            let status = manager.connection.status
            if status == .disconnected || status == .invalid {
                return true
            }
            try? await Task.sleep(nanoseconds: 50_000_000)
        }
        guard !Task.isCancelled, self.lifecycleGeneration == generation else {
            return false
        }
        let finalStatus = manager.connection.status
        return finalStatus == .disconnected || finalStatus == .invalid
    }

    @discardableResult
    func clearCache() -> Bool {
        guard clearCacheTask == nil else { return false }
        if phase == .connected,
           let session = vpnManager?.connection as? NETunnelProviderSession
        {
            clearCacheTask = Task { [weak self] in
                guard let self else { return }
                defer { self.clearCacheTask = nil }
                let data = await self.sendMessage(.clearCache, via: session)
                Self.removeAdaptiveCacheFiles()
                guard !Task.isCancelled else { return }
                if let data,
                   let res = ProviderCommandResponse.decodeData(data),
                   res.ok
                {
                    self.showToast(self.l10n.toastClearedCaches)
                    await self.fetchTelemetryOnce()
                } else {
                    self.showToast(self.l10n.toastExtensionUnreachable)
                }
            }
            return true
        } else {
            Self.removeAdaptiveCacheFiles()
            showToast(l10n.toastClearedTlsStrategies)
            return true
        }
    }

    func runDiagnostics() {
        guard !doctorState.running else { return }
        doctorState = DoctorUiState(running: true, report: nil, error: nil)
        let configJson = settings.toNativeConfigJSON()
        let wasConnected = (phase == .connected)

        doctorTask?.cancel()
        doctorTask = Task { [weak self] in
            guard let self else { return }
            defer { self.doctorTask = nil }

            if wasConnected {
                guard let session = self.vpnManager?.connection as? NETunnelProviderSession,
                      let data = await self.sendMessage(.runDoctor(configJson: configJson), via: session),
                      !Task.isCancelled,
                      let report = try? JSONDecoder().decode(DoctorReport.self, from: data),
                      !report.checks.isEmpty
                else {
                    guard !Task.isCancelled else { return }
                    self.doctorState = DoctorUiState(
                        running: false,
                        report: nil,
                        error: self.l10n.errorDiagnosticsTimeout
                    )
                    return
                }
                self.doctorState = DoctorUiState(running: false, report: report, error: nil)
                return
            }

            let report = await Task.detached(priority: .userInitiated) {
                VdpiNativeBridge.runDoctor(configJson: configJson)
            }.value
            guard !Task.isCancelled else { return }
            if report.checks.isEmpty {
                self.doctorState = DoctorUiState(
                    running: false,
                    report: nil,
                    error: self.l10n.errorDiagnosticsNoResults
                )
            } else {
                self.doctorState = DoctorUiState(running: false, report: report, error: nil)
            }
        }
    }

    func showToast(_ message: String) {
        let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        toastGeneration &+= 1
        let generation = toastGeneration
        toastTask?.cancel()
        toastMessage = trimmed
        toastTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 2_400_000_000)
            guard let self, !Task.isCancelled, self.toastGeneration == generation else { return }
            self.toastMessage = nil
            self.toastTask = nil
        }
    }

    // MARK: - Updates, Settings Backup & Diagnostics Report

    public func checkForUpdates(manual: Bool = false) {
        if isCheckingUpdate {
            if !manual || isManualUpdateCheck {
                return
            }
            updateCheckTask?.cancel()
            updateCheckTask = nil
            isCheckingUpdate = false
            isManualUpdateCheck = false
        }

        if !manual {
            let now = Date().timeIntervalSince1970
            let lastChecked = UserDefaults.standard.double(forKey: Self.lastUpdateCheckTimestampKey)
            if lastChecked > 0, (now - lastChecked) < Self.updateCheckCooldownSeconds {
                return
            }
        } else {
            lastUpdateStatusKind = nil
            updateStatusMessage = nil
        }

        isCheckingUpdate = true
        isManualUpdateCheck = manual
        let currentVersion = appVersion

        updateCheckTask = Task { [weak self] in
            let result = await VdpiUpdateChecker.fetchLatestReleaseResult(currentVersion: currentVersion)
            guard let self, !Task.isCancelled else { return }
            defer {
                self.isCheckingUpdate = false
                self.isManualUpdateCheck = false
                self.updateCheckTask = nil
            }

            switch result {
            case .failed:
                if manual {
                    self.lastUpdateStatusKind = .failed
                    self.updateStatusMessage = self.l10n.updateCheckFailed
                }
                return

            case .upToDate:
                UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: Self.lastUpdateCheckTimestampKey)
                self.availableUpdate = nil
                if manual {
                    self.lastUpdateStatusKind = .upToDate
                    self.updateStatusMessage = self.l10n.updateUpToDate
                }
                return

            case .updateAvailable(let latest):
                UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: Self.lastUpdateCheckTimestampKey)
                let dismissed = UserDefaults.standard.string(forKey: Self.dismissedUpdateVersionKey)
                if !manual, let dismissed, dismissed == latest.latestVersion {
                    self.availableUpdate = nil
                    return
                }

                if manual, dismissed == latest.latestVersion {
                    UserDefaults.standard.removeObject(forKey: Self.dismissedUpdateVersionKey)
                }

                self.availableUpdate = latest
                if manual {
                    self.lastUpdateStatusKind = .available(latest.latestVersion)
                    self.updateStatusMessage = self.l10n.updateAvailableInline(version: latest.latestVersion)
                } else {
                    self.lastUpdateStatusKind = nil
                    self.updateStatusMessage = nil
                }
            }
        }
    }

    public func dismissAvailableUpdate() {
        if let version = availableUpdate?.latestVersion {
            UserDefaults.standard.set(version, forKey: Self.dismissedUpdateVersionKey)
        }
        availableUpdate = nil
        lastUpdateStatusKind = nil
        updateStatusMessage = nil
    }

    public func exportSettingsJSON() -> String? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(settings) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    public func importSettingsJSON(_ rawJSON: String) throws {
        let normalized = try Self.parseImportedSettings(rawJSON)

        if normalized != settings {
            updateSettings { $0 = normalized }
        } else {
            VdpiAppGroup.saveSettings(normalized)
            recomputePendingReconnect(revealPopup: false)
        }
        showToast(l10n.toastImportedSettings)
    }

    nonisolated static func parseImportedSettings(_ rawJSON: String) throws -> VdpiSettings {
        let trimmed = rawJSON.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw SettingsImportError.emptyPayload
        }
        guard let data = trimmed.data(using: .utf8), data.count <= 262_144 else {
            throw SettingsImportError.invalidJSON
        }

        let parsedObject: Any
        do {
            parsedObject = try JSONSerialization.jsonObject(with: data, options: [])
        } catch {
            throw SettingsImportError.invalidJSON
        }
        guard let dict = parsedObject as? [String: Any], !dict.isEmpty else {
            throw SettingsImportError.unrecognizedFormat
        }
        guard dict.contains(where: { Self.validSettingsKeys.contains($0.key) && !($0.value is NSNull) }) else {
            throw SettingsImportError.unrecognizedFormat
        }

        let decoded: VdpiSettings
        do {
            decoded = try JSONDecoder().decode(VdpiSettings.self, from: data)
        } catch {
            throw SettingsImportError.invalidJSON
        }

        let trimmedDns = decoded.dnsAddr.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedDns = trimmedDns.isEmpty ? "1.1.1.1" : trimmedDns
        guard VdpiFormatters.isValidDnsInput(normalizedDns) else {
            throw SettingsImportError.invalidDnsAddress(normalizedDns)
        }

        var seenDomains = Set<String>()
        var normalizedBypass: [String] = []
        normalizedBypass.reserveCapacity(decoded.bypassDomains.count)
        for rawDomain in decoded.bypassDomains {
            if let cleaned = VdpiFormatters.normalizeBypassDomain(rawDomain),
               seenDomains.insert(cleaned).inserted
            {
                normalizedBypass.append(cleaned)
            }
        }
        normalizedBypass.sort()

        let normalizedEnableDoh = normalizedDns.lowercased().hasPrefix("https://")
            ? true
            : decoded.enableDoh

        return VdpiSettings(
            desyncMode: decoded.desyncMode,
            chunkSize: decoded.clampedChunkSize,
            dnsAddr: normalizedDns,
            enableDoh: normalizedEnableDoh,
            ipv4Only: decoded.ipv4Only,
            blockQuic: decoded.blockQuic,
            mtu: decoded.clampedMtu,
            bypassDomains: normalizedBypass,
            onDemandEnabled: decoded.onDemandEnabled,
            theme: decoded.theme,
            language: decoded.language
        )
    }

    public func formattedDiagnosticsReport() -> String {
        let lang = settings.language
        let loc = L10n.catalog(for: lang)
        let effectiveDoh = settings.enableDoh
            || settings.dnsAddr
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased()
                .hasPrefix("https://")
        var lines: [String] = [
            loc.reportHeader,
            "\(loc.reportAppVersion): \(appVersion)",
            "\(loc.reportEngineVersion): \(engineVersion)",
            "\(loc.reportStatus): \(phase.label(in: lang))",
            "\(loc.reportMode): \(settings.desyncMode.label(in: lang)) (\(settings.clampedChunkSize) B)",
            "DNS: \(Self.redactedDnsSummary(settings.dnsAddr)) (DoH: \(effectiveDoh ? loc.on : loc.off))",
            "\(loc.reportQuicBlocking): \(settings.blockQuic ? loc.on : loc.off)",
            "\(loc.reportIpv4Only): \(settings.ipv4Only ? loc.on : loc.off)",
            "MTU: \(settings.clampedMtu)",
            "\(loc.reportBypassRules): \(settings.bypassDomains.count)",
        ]

        lines.append("")
        if doctorState.running {
            lines.append(loc.reportProbesRunning)
        } else if let error = doctorState.error, !error.isEmpty {
            lines.append(loc.reportProbesError(Self.redactHttpsUrls(in: error)))
        } else if let report = doctorState.report, !report.checks.isEmpty {
            let passedCount = report.checks.filter(\.passed).count
            lines.append(loc.reportProbesPassedHeader(passed: passedCount, total: report.checks.count))
            for check in report.checks {
                let badge = check.passed ? loc.reportBadgePass : loc.reportBadgeFail
                let checkName = loc.doctorCheckName(check.name)
                var entry = "- [\(badge)] \(checkName) (\(check.latencyMs) ms)"
                if !check.target.isEmpty {
                    entry += " · \(Self.redactedDnsSummary(check.target))"
                }
                if !check.detail.isEmpty {
                    entry += " - \(Self.redactHttpsUrls(in: check.detail))"
                }
                lines.append(entry)
            }
        } else {
            lines.append(loc.reportProbesNotRun)
        }

        return lines.joined(separator: "\n")
    }

    // MARK: - Private NetworkExtension Wiring

    private func observeVpnStatus() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let connection = notification.object as? NEVPNConnection else { return }
            let connectionID = ObjectIdentifier(connection)
            let status = connection.status
            MainActor.assumeIsolated {
                guard let self,
                      let managerConnection = self.vpnManager?.connection,
                      ObjectIdentifier(managerConnection) == connectionID
                else { return }
                self.syncStatus(status)
            }
        }
    }

    private func loadOrCreateManager() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            guard !Task.isCancelled else { return }
            if let existing = managers.first(where: {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                    == VdpiAppGroup.extensionBundleId
            }) {
                vpnManager = existing
                // Keep user-initiated connect/disconnect state if triggered before initial load completed.
                if lifecycleTask != nil {
                    return
                }
                let status = existing.connection.status
                if status == .connected || status == .connecting || status == .reasserting {
                    appliedConfig = VdpiAppGroup.loadAppliedConfig() ?? settings.toNativeConfig()
                }
                syncStatus(status)
            } else if lifecycleTask == nil, phase == .disconnected {
                appliedConfig = nil
                VdpiAppGroup.saveAppliedConfig(nil)
                clearPendingReconnect()
            }
        } catch {
            // Simulator or unprovisioned builds without NetworkExtension entitlement stay in standby cleanly.
        }
    }

    private static func encodeSettingsJSON(_ settings: VdpiSettings) -> String? {
        guard let data = try? JSONEncoder().encode(settings) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    private func makeTunnelProtocol(for target: VdpiSettings) -> NETunnelProviderProtocol {
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = VdpiAppGroup.extensionBundleId
        proto.serverAddress = TunnelNetworkSettingsBuilder.tunnelRemoteAddress
        proto.includeAllNetworks = false
        proto.excludeLocalNetworks = true
        if #available(iOS 16.4, *) {
            proto.excludeAPNs = true
            proto.excludeCellularServices = true
        }
        if let settingsJSON = Self.encodeSettingsJSON(target) {
            proto.providerConfiguration = [Self.providerConfigSettingsKey: settingsJSON]
        }
        return proto
    }

    private func ensureConfiguredManager(for target: VdpiSettings) async throws -> NETunnelProviderManager {
        let manager: NETunnelProviderManager
        if let existing = vpnManager {
            manager = existing
        } else {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            if let found = managers.first(where: {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                    == VdpiAppGroup.extensionBundleId
            }) {
                manager = found
            } else {
                manager = NETunnelProviderManager()
            }
        }

        manager.protocolConfiguration = makeTunnelProtocol(for: target)
        manager.localizedDescription = "vdpi"
        manager.isEnabled = true
        applyOnDemandRules(to: manager, enabled: target.onDemandEnabled)

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        vpnManager = manager
        return manager
    }

    private func syncOnDemandPreference() async {
        await loadTask?.value
        guard !Task.isCancelled, let manager = vpnManager else { return }
        try? await manager.loadFromPreferences()
        guard !Task.isCancelled else { return }
        applyOnDemandRules(to: manager, enabled: settings.onDemandEnabled)
        try? await manager.saveToPreferences()
        guard !Task.isCancelled else { return }
        try? await manager.loadFromPreferences()
    }

    private func applyOnDemandRules(to manager: NETunnelProviderManager, enabled: Bool) {
        manager.isOnDemandEnabled = enabled
        if enabled {
            let connectRule = NEOnDemandRuleConnect()
            connectRule.interfaceTypeMatch = .any
            manager.onDemandRules = [connectRule]
        } else {
            manager.onDemandRules = nil
        }
    }

    private func clearPendingReconnect() {
        if pendingReconnect {
            pendingReconnect = false
        }
        if reconnectPopupVisible {
            reconnectPopupVisible = false
        }
        if !pendingChangeSummary.isEmpty {
            pendingChangeSummary = ""
        }
    }

    private func recomputePendingReconnect(revealPopup: Bool) {
        guard phase == .connected || phase == .connecting,
              let applied = appliedConfig
        else {
            clearPendingReconnect()
            return
        }

        let summary = settings.pendingChangeSummary(
            comparedToApplied: applied,
            language: settings.language
        )
        if summary.isEmpty {
            clearPendingReconnect()
        } else {
            if !pendingReconnect {
                pendingReconnect = true
            }
            if pendingChangeSummary != summary {
                pendingChangeSummary = summary
            }
            if revealPopup && !reconnectPopupVisible {
                reconnectPopupVisible = true
            }
        }
    }

    private func syncStatus(_ status: NEVPNStatus) {
        let previousPhase = phase
        switch status {
        case .connected:
            userInitiatedDisconnect = false
            engineUnhealthyWhileConnected = false
            disconnectErrorGeneration &+= 1
            phase = .connected
            errorMessage = nil
            if let persisted = VdpiAppGroup.loadAppliedConfig() {
                appliedConfig = persisted
            } else if appliedConfig == nil {
                appliedConfig = settings.toNativeConfig()
            }
            recomputePendingReconnect(revealPopup: false)
            if isSceneActive {
                startTelemetryPolling()
            }
        case .connecting, .reasserting:
            userInitiatedDisconnect = false
            engineUnhealthyWhileConnected = false
            disconnectErrorGeneration &+= 1
            phase = .connecting
            errorMessage = nil
            if appliedConfig == nil {
                appliedConfig = VdpiAppGroup.loadAppliedConfig() ?? settings.toNativeConfig()
            }
            recomputePendingReconnect(revealPopup: false)
        case .disconnecting:
            phase = .disconnecting
            clearPendingReconnect()
            telemetryTask?.cancel()
            telemetryTask = nil
        case .disconnected, .invalid:
            let wasUserInitiated = userInitiatedDisconnect
            userInitiatedDisconnect = false
            engineUnhealthyWhileConnected = false

            let preserveFreshError = (previousPhase == .error)
                && !(errorMessage?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
            let shouldFetchDisconnectError = !wasUserInitiated
                && !preserveFreshError
                && (previousPhase == .connecting || previousPhase == .connected || previousPhase == .disconnecting)

            if !preserveFreshError {
                phase = .disconnected
            }
            appliedConfig = nil
            VdpiAppGroup.saveAppliedConfig(nil)
            clearPendingReconnect()
            telemetryTask?.cancel()
            telemetryTask = nil
            resetThroughputHistory()
            telemetry = TelemetrySnapshot(
                running: false,
                uptimeSecs: 0,
                activeConnections: 0,
                totalConnections: 0,
                bytesTx: 0,
                bytesRx: 0,
                tlsHandshakes: 0,
                autoHealEscalations: 0,
                dnsQueries: 0,
                quicBlocked: 0,
                udpFlowsActive: 0,
                learnedHosts: 0,
                stageNumber: 1,
                stageLabel: "ComboMultiRecord",
                dnsAddr: settings.dnsAddr,
                dohEnabled: settings.enableDoh,
                events: telemetry.events
            )

            if shouldFetchDisconnectError, let connection = vpnManager?.connection {
                fetchAndSurfaceLastDisconnectError(from: connection)
            }
        @unknown default:
            userInitiatedDisconnect = false
            engineUnhealthyWhileConnected = false
            phase = .disconnected
            appliedConfig = nil
            VdpiAppGroup.saveAppliedConfig(nil)
            clearPendingReconnect()
            telemetryTask?.cancel()
            telemetryTask = nil
            resetThroughputHistory()
        }
    }

    private func fetchAndSurfaceLastDisconnectError(from connection: NEVPNConnection) {
        disconnectErrorGeneration &+= 1
        let disconnectGen = disconnectErrorGeneration
        let lifecycleGen = lifecycleGeneration
        connection.fetchLastDisconnectError { [weak self] error in
            guard let error, let self else { return }
            let message = Self.userFacingDisconnectError(from: error as NSError)
            guard let message else { return }
            Task { @MainActor [weak self] in
                guard let self,
                      self.lifecycleGeneration == lifecycleGen,
                      self.disconnectErrorGeneration == disconnectGen,
                      self.phase == .disconnected
                else { return }
                self.phase = .error
                self.errorMessage = message
                self.triggerNotificationHaptic(.error)
            }
        }
    }

    private nonisolated static func userFacingDisconnectError(from error: NSError) -> String? {
        if error.domain == NSCocoaErrorDomain && error.code == NSUserCancelledError {
            return nil
        }
        if error.domain == "com.vulninc.vdpi.tunnel" && error.code == 1002 {
            return nil
        }
        if error.domain == NEVPNConnectionErrorDomain && error.code == 0 {
            return nil
        }
        let trimmed = error.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private func startTelemetryPolling() {
        telemetryTask?.cancel()
        telemetryTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { break }
                await self.fetchTelemetryOnce()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }

    private func fetchTelemetryOnce() async {
        guard phase == .connected,
              let session = vpnManager?.connection as? NETunnelProviderSession
        else { return }
        guard let data = await sendMessage(.snapshot, via: session),
              !Task.isCancelled,
              phase == .connected,
              let decoded = try? JSONDecoder().decode(TelemetrySnapshot.self, from: data)
        else { return }
        if !decoded.running {
            if telemetry != decoded {
                telemetry = decoded
            }
            guard !isReloading, vpnManager?.connection.status == .connected else {
                consecutiveUnhealthySamples = 0
                return
            }
            // Require 2 consecutive `running == false` samples (~2s) so brief extension-initiated
            // route-change reloads never falsely lock the UI into `.error`.
            consecutiveUnhealthySamples += 1
            guard consecutiveUnhealthySamples >= 2 else { return }
            engineUnhealthyWhileConnected = true
            telemetryTask?.cancel()
            telemetryTask = nil
            resetThroughputHistory()
            phase = .error
            errorMessage = l10n.errorEngineNotRunning
            triggerNotificationHaptic(.error)
            return
        }
        consecutiveUnhealthySamples = 0
        engineUnhealthyWhileConnected = false
        recordThroughputSample(from: decoded)
        if telemetry != decoded {
            telemetry = decoded
        }
    }

    private func recordThroughputSample(from snapshot: TelemetrySnapshot) {
        let nowNs = DispatchTime.now().uptimeNanoseconds
        let (sumBytes, overflowed) = snapshot.bytesTx.addingReportingOverflow(snapshot.bytesRx)
        let totalBytes = overflowed ? UInt64.max : sumBytes

        guard let previousBytes = lastThroughputTotalBytes,
              let previousNs = lastThroughputUptimeNs,
              nowNs > previousNs
        else {
            lastThroughputTotalBytes = totalBytes
            lastThroughputUptimeNs = nowNs
            return
        }

        let elapsedNs = nowNs - previousNs
        // Avoid artificial rate spikes when manual IPC fetches run back-to-back with the 1s poll.
        guard elapsedNs >= 200_000_000 else { return }

        lastThroughputTotalBytes = totalBytes
        lastThroughputUptimeNs = nowNs

        let deltaBytes: UInt64 = totalBytes >= previousBytes ? (totalBytes - previousBytes) : 0
        let elapsedSec = Double(elapsedNs) / 1_000_000_000.0
        let rawRate = (Double(deltaBytes) / elapsedSec).rounded()
        let rate: UInt64
        if rawRate.isFinite && rawRate > 0 && rawRate < Double(UInt64.max) {
            rate = UInt64(rawRate)
        } else if rawRate.isFinite && rawRate >= Double(UInt64.max) {
            rate = UInt64.max
        } else {
            rate = 0
        }

        currentRateBytesPerSec = rate
        var samples = throughputSamples
        samples.append(rate)
        if samples.count > Self.maxThroughputSamples {
            samples.removeFirst(samples.count - Self.maxThroughputSamples)
        }
        throughputSamples = samples
    }

    private func resetThroughputHistory() {
        lastThroughputTotalBytes = nil
        lastThroughputUptimeNs = nil
        if currentRateBytesPerSec != 0 {
            currentRateBytesPerSec = 0
        }
        if !throughputSamples.isEmpty {
            throughputSamples = []
        }
    }

    private static func removeAdaptiveCacheFiles() {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: VdpiAppGroup.suiteName
        ) else { return }
        for filename in ["adaptive-cache.json", "adaptive-cache.tmp", "adaptive-cache.json.tmp"] {
            let fileURL = containerURL.appendingPathComponent(filename)
            if FileManager.default.fileExists(atPath: fileURL.path) {
                try? FileManager.default.removeItem(at: fileURL)
            }
        }
    }

    nonisolated static func redactedDnsSummary(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "1.1.1.1" }
        if let arrowRange = trimmed.range(of: " -> ") {
            let leading = String(trimmed[..<arrowRange.lowerBound])
            let trailing = String(trimmed[arrowRange.upperBound...])
            let redactedLeading = redactSingleDnsEndpoint(leading)
            let trimmedTrailing = trailing.trimmingCharacters(in: .whitespacesAndNewlines)
            let redactedTrailing = trimmedTrailing.lowercased().hasPrefix("https://")
                ? redactSingleDnsEndpoint(trimmedTrailing)
                : trailing
            return "\(redactedLeading) -> \(redactedTrailing)"
        }
        return redactSingleDnsEndpoint(trimmed)
    }

    nonisolated static func redactHttpsUrls(in text: String) -> String {
        guard text.range(of: "https://", options: .caseInsensitive) != nil,
              let regex = try? NSRegularExpression(
                  pattern: #"https://[^\s"'<>]+"#,
                  options: [.caseInsensitive]
              )
        else {
            return text
        }
        let mutable = NSMutableString(string: text)
        let fullRange = NSRange(location: 0, length: mutable.length)
        let matches = regex.matches(in: text, options: [], range: fullRange)
        guard !matches.isEmpty else { return text }

        for match in matches.reversed() {
            let rawToken = mutable.substring(with: match.range)
            var urlPart = rawToken
            var trailing = ""
            while let last = urlPart.last {
                if last == "." || last == "," || last == ";" || last == ":" {
                    trailing.insert(last, at: trailing.startIndex)
                    urlPart.removeLast()
                } else if last == "]" {
                    let openCount = urlPart.filter { $0 == "[" }.count
                    let closeCount = urlPart.filter { $0 == "]" }.count
                    if closeCount > openCount {
                        trailing.insert(last, at: trailing.startIndex)
                        urlPart.removeLast()
                    } else {
                        break
                    }
                } else if last == ")" {
                    let openCount = urlPart.filter { $0 == "(" }.count
                    let closeCount = urlPart.filter { $0 == ")" }.count
                    if closeCount > openCount {
                        trailing.insert(last, at: trailing.startIndex)
                        urlPart.removeLast()
                    } else {
                        break
                    }
                } else {
                    break
                }
            }
            let replacement = redactSingleDnsEndpoint(urlPart) + trailing
            mutable.replaceCharacters(in: match.range, with: replacement)
        }
        return mutable as String
    }

    private nonisolated static func redactSingleDnsEndpoint(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "1.1.1.1" }
        guard trimmed.lowercased().hasPrefix("https://") else {
            return trimmed
        }
        guard let components = URLComponents(string: trimmed),
              let host = components.host,
              !host.isEmpty
        else {
            return "Custom DoH"
        }
        let formattedHost: String
        if host.contains(":") && !(host.hasPrefix("[") && host.hasSuffix("]")) {
            formattedHost = "[\(host)]"
        } else {
            formattedHost = host
        }
        let portSuffix = components.port.map { ":\($0)" } ?? ""
        let path = components.path
        let hasSensitiveQueryOrFragment = (components.query != nil) || (components.fragment != nil)
        if !hasSensitiveQueryOrFragment && (path.isEmpty || path == "/" || path == "/dns-query") {
            return "https://\(formattedHost)\(portSuffix)\(path)"
        }
        return "https://\(formattedHost)\(portSuffix)/[redacted]"
    }

    private static func timeoutSeconds(for message: ProviderMessage) -> TimeInterval {
        switch message {
        case .snapshot, .clearCache:
            return 5
        case .reloadEngine, .reloadEngineWithSettings:
            return 15
        case .runDoctor:
            return 35
        }
    }

    private func sendMessage(
        _ message: ProviderMessage,
        via session: NETunnelProviderSession
    ) async -> Data? {
        guard !Task.isCancelled, let payload = message.encodeData() else { return nil }
        let timeout = Self.timeoutSeconds(for: message)
        let box = ProviderMessageBox()

        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                box.install(continuation: continuation, timeoutSeconds: timeout)
                if Task.isCancelled {
                    box.finish(with: nil)
                    return
                }
                do {
                    try session.sendProviderMessage(payload) { response in
                        box.finish(with: response)
                    }
                } catch {
                    box.finish(with: nil)
                }
            }
        } onCancel: {
            box.finish(with: nil)
        }
    }

    private func triggerHaptic(_ style: UIImpactFeedbackGenerator.FeedbackStyle) {
        let generator = UIImpactFeedbackGenerator(style: style)
        generator.prepare()
        generator.impactOccurred()
    }

    private func triggerNotificationHaptic(_ type: UINotificationFeedbackGenerator.FeedbackType) {
        let generator = UINotificationFeedbackGenerator()
        generator.prepare()
        generator.notificationOccurred(type)
    }
}

private final class ProviderMessageBox: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data?, Never>?
    private var timeoutWorkItem: DispatchWorkItem?
    private var finished = false

    func install(
        continuation: CheckedContinuation<Data?, Never>,
        timeoutSeconds: TimeInterval
    ) {
        lock.lock()
        if finished {
            lock.unlock()
            continuation.resume(returning: nil)
            return
        }
        self.continuation = continuation
        let workItem = DispatchWorkItem { [weak self] in
            self?.finish(with: nil)
        }
        self.timeoutWorkItem = workItem
        lock.unlock()

        DispatchQueue.global(qos: .utility).asyncAfter(
            deadline: .now() + timeoutSeconds,
            execute: workItem
        )
    }

    func finish(with data: Data?) {
        lock.lock()
        guard !finished else {
            lock.unlock()
            return
        }
        finished = true
        let cont = continuation
        continuation = nil
        let workItem = timeoutWorkItem
        timeoutWorkItem = nil
        lock.unlock()

        workItem?.cancel()
        cont?.resume(returning: data)
    }
}
