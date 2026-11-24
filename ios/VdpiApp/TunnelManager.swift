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
        switch self {
        case .disconnected: return "Standby"
        case .connecting: return "Connecting"
        case .connected: return "Protected"
        case .disconnecting: return "Stopping"
        case .error: return "Error"
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

    public var errorDescription: String? {
        switch self {
        case .emptyPayload:
            return "Settings backup is empty."
        case .invalidJSON:
            return "Settings backup is not valid JSON."
        case .unrecognizedFormat:
            return "JSON does not contain recognized vdpi settings."
        case .invalidDnsAddress(let addr):
            return "Invalid DNS address in settings backup: \(addr)"
        }
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
        return "0.4.0"
    }

    private static let maxThroughputSamples = 24
    private static let updateCheckCooldownSeconds: TimeInterval = 6 * 60 * 60
    private static let lastUpdateCheckTimestampKey = "vdpi_last_update_check_ts_v1"
    private static let dismissedUpdateVersionKey = "vdpi_dismissed_update_version_v1"
    private static let validSettingsKeys: Set<String> = [
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
    ]

    private var vpnManager: NETunnelProviderManager?
    private var appliedConfig: NativeEngineConfig?
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
    private var lastThroughputTotalBytes: UInt64?
    private var lastThroughputUptimeNs: UInt64?
    private var reloadGeneration: UInt64 = 0
    private var lifecycleGeneration: UInt64 = 0
    private var toastGeneration: UInt64 = 0
    private var isSceneActive: Bool = true

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
        if active && phase == .connected {
            startTelemetryPolling()
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
        }

        if onDemandChanged {
            onDemandSyncTask?.cancel()
            onDemandSyncTask = Task { [weak self] in
                await self?.syncOnDemandPreference()
            }
        }
    }

    func dismissReconnectPopup() {
        if reconnectPopupVisible {
            reconnectPopupVisible = false
        }
    }

    func resetSettings() {
        let defaults = VdpiSettings(theme: settings.theme)
        updateSettings { $0 = defaults }
        showToast("Settings reset to defaults")
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

        lifecycleGeneration &+= 1
        let generation = lifecycleGeneration
        lifecycleTask?.cancel()
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
                let manager = try await self.ensureConfiguredManager(for: target)
                guard !Task.isCancelled else { return }
                let launchTarget = self.settings
                VdpiAppGroup.saveSettings(launchTarget)
                let applied = launchTarget.toNativeConfig()
                self.appliedConfig = applied
                VdpiAppGroup.saveAppliedConfig(applied)
                try manager.connection.startVPNTunnel()
                self.recomputePendingReconnect(revealPopup: false)
                self.triggerHaptic(.medium)
            } catch {
                guard !Task.isCancelled else { return }
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

        lifecycleGeneration &+= 1
        let generation = lifecycleGeneration
        lifecycleTask?.cancel()
        lifecycleTask = nil
        errorMessage = nil
        appliedConfig = nil
        VdpiAppGroup.saveAppliedConfig(nil)
        clearPendingReconnect()

        guard let manager = vpnManager else {
            phase = .disconnected
            telemetryTask?.cancel()
            telemetryTask = nil
            resetThroughputHistory()
            return
        }

        let initialStatus = manager.connection.status
        if initialStatus == .disconnected || initialStatus == .invalid {
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
                    manager.isOnDemandEnabled = false
                    try? await manager.saveToPreferences()
                    guard !Task.isCancelled else { return }
                    try? await manager.loadFromPreferences()
                }
            }
            return
        }

        phase = .disconnecting
        triggerHaptic(.light)

        // Disable On-Demand before stopping so an explicit user disconnect is not
        // immediately overridden by NEOnDemandRuleConnect on the next packet.
        lifecycleTask = Task { [weak self] in
            defer {
                if let self, self.lifecycleGeneration == generation {
                    self.lifecycleTask = nil
                }
            }
            if manager.isOnDemandEnabled {
                manager.isOnDemandEnabled = false
                try? await manager.saveToPreferences()
                guard !Task.isCancelled else { return }
                try? await manager.loadFromPreferences()
                guard !Task.isCancelled else { return }
            }
            guard let self, !Task.isCancelled else { return }
            let currentStatus = manager.connection.status
            if currentStatus == .disconnected || currentStatus == .invalid {
                self.phase = .disconnected
                self.telemetryTask?.cancel()
                self.telemetryTask = nil
                self.resetThroughputHistory()
                return
            }
            manager.connection.stopVPNTunnel()
        }
    }

    func applyChangesLive() {
        guard !isReloading else { return }
        let target = settings
        VdpiAppGroup.saveSettings(target)

        if phase == .connected,
           let session = vpnManager?.connection as? NETunnelProviderSession
        {
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

                let replyData = await self.sendMessage(.reloadEngine, via: session)
                guard !Task.isCancelled, self.reloadGeneration == generation else { return }

                if let replyData,
                   let response = ProviderCommandResponse.decodeData(replyData),
                   response.ok
                {
                    let persisted = VdpiAppGroup.loadAppliedConfig()?.canonicalized()
                    let applied = persisted ?? target.toNativeConfig()
                    self.appliedConfig = applied
                    if persisted == nil {
                        VdpiAppGroup.saveAppliedConfig(applied)
                    }
                    self.clearPendingReconnect()
                    // Re-check in case another runtime setting changed while reload was in flight.
                    if self.settings.requiresTunnelReload(comparedToApplied: applied) {
                        self.recomputePendingReconnect(revealPopup: true)
                    }
                    if self.reloadGeneration == generation {
                        self.isReloading = false
                    }
                    self.triggerNotificationHaptic(.success)
                    self.showToast("Applied updated settings")
                    await self.fetchTelemetryOnce()
                } else {
                    // Fallback to full reconnect if live reload failed.
                    guard self.phase != .disconnecting else { return }
                    if self.phase != .disconnected {
                        self.vpnManager?.connection.stopVPNTunnel()
                        try? await Task.sleep(nanoseconds: 350_000_000)
                        guard !Task.isCancelled, self.reloadGeneration == generation else { return }
                    }
                    self.connect()
                }
            }
            return
        }

        if phase == .connecting, let manager = vpnManager {
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
                manager.connection.stopVPNTunnel()
                try? await Task.sleep(nanoseconds: 350_000_000)
                guard !Task.isCancelled, self.reloadGeneration == generation else { return }
                self.connect()
            }
            return
        }

        connect()
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
                    self.showToast("Cleared TLS & DNS caches")
                    await self.fetchTelemetryOnce()
                } else {
                    self.showToast("Could not reach tunnel extension")
                }
            }
            return true
        } else {
            Self.removeAdaptiveCacheFiles()
            showToast("Cleared cached TLS strategies")
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
                        error: "Diagnostics timed out or the tunnel extension did not respond."
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
                    error: "Native diagnostics returned no probe results."
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
                    self.updateStatusMessage = "Check failed"
                }
                return

            case .upToDate:
                UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: Self.lastUpdateCheckTimestampKey)
                self.availableUpdate = nil
                if manual {
                    self.updateStatusMessage = "Up to date"
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
                self.updateStatusMessage = manual ? "Update available: v\(latest.latestVersion)" : nil
            }
        }
    }

    public func dismissAvailableUpdate() {
        if let version = availableUpdate?.latestVersion {
            UserDefaults.standard.set(version, forKey: Self.dismissedUpdateVersionKey)
        }
        availableUpdate = nil
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

        let normalized = VdpiSettings(
            desyncMode: decoded.desyncMode,
            chunkSize: decoded.clampedChunkSize,
            dnsAddr: normalizedDns,
            enableDoh: decoded.enableDoh,
            ipv4Only: decoded.ipv4Only,
            blockQuic: decoded.blockQuic,
            mtu: decoded.clampedMtu,
            bypassDomains: normalizedBypass,
            onDemandEnabled: decoded.onDemandEnabled,
            theme: decoded.theme
        )

        if normalized != settings {
            updateSettings { $0 = normalized }
        } else {
            VdpiAppGroup.saveSettings(normalized)
            recomputePendingReconnect(revealPopup: false)
        }
        showToast("Imported settings")
    }

    public func formattedDiagnosticsReport() -> String {
        var lines: [String] = [
            "vdpi Diagnostics Report",
            "App Version: \(appVersion)",
            "Engine Version: \(engineVersion)",
            "Status: \(phase.label)",
            "Mode: \(settings.desyncMode.label) (\(settings.clampedChunkSize) B)",
            "DNS: \(Self.redactedDnsSummary(settings.dnsAddr)) (DoH: \(settings.enableDoh ? "On" : "Off"))",
            "QUIC Blocking: \(settings.blockQuic ? "On" : "Off")",
            "IPv4 Only: \(settings.ipv4Only ? "On" : "Off")",
            "MTU: \(settings.clampedMtu)",
            "Bypass Rules: \(settings.bypassDomains.count)",
        ]

        lines.append("")
        if doctorState.running {
            lines.append("Diagnostics Probes: Running...")
        } else if let error = doctorState.error, !error.isEmpty {
            lines.append("Diagnostics Probes: Error - \(error)")
        } else if let report = doctorState.report, !report.checks.isEmpty {
            let passedCount = report.checks.filter(\.passed).count
            lines.append("Diagnostics Probes (\(passedCount)/\(report.checks.count) passed):")
            for check in report.checks {
                let badge = check.passed ? "PASS" : "FAIL"
                var entry = "- [\(badge)] \(check.name) (\(check.latencyMs) ms)"
                if !check.target.isEmpty {
                    entry += " · \(Self.redactedDnsSummary(check.target))"
                }
                if !check.detail.isEmpty {
                    entry += " - \(check.detail)"
                }
                lines.append(entry)
            }
        } else {
            lines.append("Diagnostics Probes: Not run")
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
                let status = existing.connection.status
                // Keep user-initiated connect/disconnect state if triggered before initial load completed.
                if lifecycleTask != nil, status == .disconnected || status == .invalid {
                    return
                }
                if status == .connected || status == .connecting || status == .reasserting {
                    appliedConfig = VdpiAppGroup.loadAppliedConfig() ?? settings.toNativeConfig()
                }
                syncStatus(status)
            } else if phase == .disconnected {
                appliedConfig = nil
                VdpiAppGroup.saveAppliedConfig(nil)
                clearPendingReconnect()
            }
        } catch {
            // Simulator or unprovisioned builds without NetworkExtension entitlement stay in standby cleanly.
        }
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

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = VdpiAppGroup.extensionBundleId
        proto.serverAddress = TunnelNetworkSettingsBuilder.tunnelRemoteAddress
        proto.includeAllNetworks = false

        manager.protocolConfiguration = proto
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

        let summary = settings.pendingChangeSummary(comparedToApplied: applied)
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
        switch status {
        case .connected:
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
            phase = .connecting
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
            phase = .disconnected
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
        @unknown default:
            phase = .disconnected
            appliedConfig = nil
            VdpiAppGroup.saveAppliedConfig(nil)
            clearPendingReconnect()
            telemetryTask?.cancel()
            telemetryTask = nil
            resetThroughputHistory()
        }
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

    private static func redactedDnsSummary(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "1.1.1.1" }
        if let arrowRange = trimmed.range(of: " -> ") {
            let leading = String(trimmed[..<arrowRange.lowerBound])
            let trailing = String(trimmed[arrowRange.upperBound...])
            let redactedLeading = redactSingleDnsEndpoint(leading)
            return "\(redactedLeading) -> \(trailing)"
        }
        return redactSingleDnsEndpoint(trimmed)
    }

    private static func redactSingleDnsEndpoint(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.lowercased().hasPrefix("https://"),
              let components = URLComponents(string: trimmed),
              let host = components.host,
              !host.isEmpty
        else {
            return trimmed.isEmpty ? "1.1.1.1" : trimmed
        }
        let portSuffix = components.port.map { ":\($0)" } ?? ""
        let path = components.path
        let hasSensitiveQueryOrFragment = (components.query != nil) || (components.fragment != nil)
        if !hasSensitiveQueryOrFragment && (path.isEmpty || path == "/" || path == "/dns-query") {
            return "https://\(host)\(portSuffix)\(path)"
        }
        return "https://\(host)\(portSuffix)/[redacted]"
    }

    private static func timeoutSeconds(for message: ProviderMessage) -> TimeInterval {
        switch message {
        case .snapshot, .clearCache:
            return 5
        case .reloadEngine:
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
