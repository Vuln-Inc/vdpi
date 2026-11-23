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
    public var running: Bool = false
    public var report: DoctorReport? = nil
    public var error: String? = nil
}

@MainActor
final class TunnelManager: ObservableObject {
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

    let engineVersion: String

    private var vpnManager: NETunnelProviderManager?
    private var appliedConfig: NativeEngineConfig?
    private var statusObserver: NSObjectProtocol?
    private var loadTask: Task<Void, Never>?
    private var lifecycleTask: Task<Void, Never>?
    private var reloadTask: Task<Void, Never>?
    private var onDemandSyncTask: Task<Void, Never>?
    private var clearCacheTask: Task<Void, Never>?
    private var doctorTask: Task<Void, Never>?
    private var telemetryTask: Task<Void, Never>?
    private var toastTask: Task<Void, Never>?
    private var reloadGeneration: UInt64 = 0
    private var lifecycleGeneration: UInt64 = 0
    private var toastGeneration: UInt64 = 0
    private var isSceneActive: Bool = true

    init() {
        let loaded = VdpiAppGroup.loadSettings()
        self.settings = loaded
        self.appliedConfig = VdpiAppGroup.loadAppliedConfig()
        self.engineVersion = VdpiNativeBridge.version()
        observeVpnStatus()
        loadTask = Task { [weak self] in
            await self?.loadOrCreateManager()
        }
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
    }

    func setSceneActive(_ active: Bool) {
        isSceneActive = active
        if active && phase == .connected {
            startTelemetryPolling()
        } else {
            telemetryTask?.cancel()
            telemetryTask = nil
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
            guard self != nil, !Task.isCancelled else { return }
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
                if let data = await self.sendMessage(.clearCache, via: session),
                   !Task.isCancelled,
                   let res = ProviderCommandResponse.decodeData(data),
                   res.ok
                {
                    self.showToast("Cleared TLS & DNS caches")
                    await self.fetchTelemetryOnce()
                } else if !Task.isCancelled {
                    self.showToast("Could not reach tunnel extension")
                }
            }
            return true
        } else {
            showToast("Cache resets automatically when disconnected")
            return false
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
        if telemetry != decoded {
            telemetry = decoded
        }
    }

    private func sendMessage(
        _ message: ProviderMessage,
        via session: NETunnelProviderSession
    ) async -> Data? {
        guard let payload = message.encodeData() else { return nil }
        return await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(payload) { response in
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(returning: nil)
            }
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
