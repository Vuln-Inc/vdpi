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
    private var telemetryTask: Task<Void, Never>?
    private var toastTask: Task<Void, Never>?
    private var isSceneActive: Bool = true

    init() {
        let loaded = VdpiAppGroup.loadSettings()
        self.settings = loaded
        self.engineVersion = VdpiNativeBridge.version()
        observeVpnStatus()
        loadTask = Task {
            await loadOrCreateManager()
        }
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        loadTask?.cancel()
        lifecycleTask?.cancel()
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
        let nativeConfigChanged = next.toNativeConfig() != previous.toNativeConfig()
        settings = next
        VdpiAppGroup.saveSettings(next)

        if nativeConfigChanged {
            recomputePendingReconnect(revealPopup: true)
        }

        if onDemandChanged {
            Task {
                await syncOnDemandPreference()
            }
        }
    }

    func dismissReconnectPopup() {
        reconnectPopupVisible = false
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
        lifecycleTask?.cancel()
        errorMessage = nil
        phase = .connecting
        let target = settings
        VdpiAppGroup.saveSettings(target)

        lifecycleTask = Task {
            await loadTask?.value
            guard !Task.isCancelled else { return }
            do {
                let manager = try await ensureConfiguredManager(for: target)
                guard !Task.isCancelled else { return }
                let applied = target.toNativeConfig()
                appliedConfig = applied
                VdpiAppGroup.saveAppliedConfig(applied)
                pendingReconnect = false
                reconnectPopupVisible = false
                pendingChangeSummary = ""
                try manager.connection.startVPNTunnel()
                recomputePendingReconnect(revealPopup: false)
                triggerHaptic(.medium)
            } catch {
                guard !Task.isCancelled else { return }
                phase = .error
                errorMessage = error.localizedDescription
                appliedConfig = nil
                VdpiAppGroup.saveAppliedConfig(nil)
                recomputePendingReconnect(revealPopup: false)
                triggerNotificationHaptic(.error)
            }
        }
    }

    func disconnect() {
        lifecycleTask?.cancel()
        errorMessage = nil
        appliedConfig = nil
        VdpiAppGroup.saveAppliedConfig(nil)
        pendingReconnect = false
        reconnectPopupVisible = false
        pendingChangeSummary = ""

        guard let manager = vpnManager else {
            phase = .disconnected
            return
        }

        phase = .disconnecting
        triggerHaptic(.light)

        // Disable On-Demand before stopping so an explicit user disconnect is not
        // immediately overridden by NEOnDemandRuleConnect on the next packet.
        lifecycleTask = Task {
            if manager.isOnDemandEnabled {
                manager.isOnDemandEnabled = false
                try? await manager.saveToPreferences()
                try? await manager.loadFromPreferences()
            }
            manager.connection.stopVPNTunnel()
        }
    }

    func applyChangesLive() {
        guard !isReloading else { return }
        let target = settings
        VdpiAppGroup.saveSettings(target)
        guard phase == .connected,
              let session = vpnManager?.connection as? NETunnelProviderSession
        else {
            connect()
            return
        }

        isReloading = true
        Task {
            defer { isReloading = false }
            let replyData = await sendMessage(.reloadEngine, via: session)
            if let replyData,
               let response = ProviderCommandResponse.decodeData(replyData),
               response.ok
            {
                let applied = target.toNativeConfig()
                appliedConfig = applied
                VdpiAppGroup.saveAppliedConfig(applied)
                pendingReconnect = false
                reconnectPopupVisible = false
                pendingChangeSummary = ""
                recomputePendingReconnect(revealPopup: false)
                triggerNotificationHaptic(.success)
                showToast("Applied updated settings")
                await fetchTelemetryOnce()
            } else {
                // Fallback to full reconnect if live reload failed.
                vpnManager?.connection.stopVPNTunnel()
                try? await Task.sleep(nanoseconds: 350_000_000)
                connect()
            }
        }
    }

    func clearCache() {
        if phase == .connected,
           let session = vpnManager?.connection as? NETunnelProviderSession
        {
            Task {
                if let data = await sendMessage(.clearCache, via: session),
                   let res = ProviderCommandResponse.decodeData(data),
                   res.ok
                {
                    showToast("Cleared TLS & DNS caches")
                    await fetchTelemetryOnce()
                } else {
                    showToast("Could not reach tunnel extension")
                }
            }
        } else {
            showToast("Cache resets automatically when disconnected")
        }
    }

    func runDiagnostics() {
        guard !doctorState.running else { return }
        doctorState = DoctorUiState(running: true, report: nil, error: nil)
        let configJson = settings.toNativeConfigJSON()
        let wasConnected = (phase == .connected)

        Task {
            if wasConnected {
                guard let session = vpnManager?.connection as? NETunnelProviderSession,
                      let data = await sendMessage(.runDoctor(configJson: configJson), via: session),
                      let report = try? JSONDecoder().decode(DoctorReport.self, from: data),
                      !report.checks.isEmpty
                else {
                    doctorState = DoctorUiState(
                        running: false,
                        report: nil,
                        error: "Diagnostics timed out or the tunnel extension did not respond."
                    )
                    return
                }
                doctorState = DoctorUiState(running: false, report: report, error: nil)
                return
            }

            let report = await Task.detached(priority: .userInitiated) {
                VdpiNativeBridge.runDoctor(configJson: configJson)
            }.value
            if report.checks.isEmpty {
                doctorState = DoctorUiState(
                    running: false,
                    report: nil,
                    error: "Native diagnostics returned no probe results."
                )
            } else {
                doctorState = DoctorUiState(running: false, report: report, error: nil)
            }
        }
    }

    func showToast(_ message: String) {
        toastTask?.cancel()
        toastMessage = message
        toastTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 2_400_000_000)
            guard !Task.isCancelled else { return }
            self?.toastMessage = nil
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
            let status = connection.status
            MainActor.assumeIsolated {
                guard let self, connection === self.vpnManager?.connection else { return }
                self.syncStatus(status)
            }
        }
    }

    private func loadOrCreateManager() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            if let existing = managers.first(where: {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                    == VdpiAppGroup.extensionBundleId
            }) {
                vpnManager = existing
                let status = existing.connection.status
                if status == .connected || status == .connecting || status == .reasserting {
                    appliedConfig = VdpiAppGroup.loadAppliedConfig() ?? settings.toNativeConfig()
                }
                syncStatus(status)
                recomputePendingReconnect(revealPopup: false)
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
        guard let manager = vpnManager else { return }
        try? await manager.loadFromPreferences()
        applyOnDemandRules(to: manager, enabled: settings.onDemandEnabled)
        try? await manager.saveToPreferences()
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

    private func recomputePendingReconnect(revealPopup: Bool) {
        guard phase == .connected || phase == .connecting,
              let applied = appliedConfig
        else {
            pendingReconnect = false
            reconnectPopupVisible = false
            pendingChangeSummary = ""
            return
        }

        let labels = settings.changedFieldLabels(comparedToApplied: applied)
        if labels.isEmpty {
            pendingReconnect = false
            reconnectPopupVisible = false
            pendingChangeSummary = ""
        } else {
            pendingReconnect = true
            pendingChangeSummary = labels.joined(separator: ", ")
            if revealPopup {
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
            if appliedConfig == nil, let persisted = VdpiAppGroup.loadAppliedConfig() {
                appliedConfig = persisted
            }
            recomputePendingReconnect(revealPopup: false)
        case .disconnecting:
            phase = .disconnecting
            recomputePendingReconnect(revealPopup: false)
            telemetryTask?.cancel()
            telemetryTask = nil
        case .disconnected, .invalid:
            phase = .disconnected
            appliedConfig = nil
            VdpiAppGroup.saveAppliedConfig(nil)
            recomputePendingReconnect(revealPopup: false)
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
            recomputePendingReconnect(revealPopup: false)
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
