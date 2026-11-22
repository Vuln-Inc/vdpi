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
    @Published var toastMessage: String? = nil

    let engineVersion: String

    private var vpnManager: NETunnelProviderManager?
    private var appliedSettings: VdpiSettings?
    private var statusObserver: NSObjectProtocol?
    private var telemetryTask: Task<Void, Never>?
    private var toastTask: Task<Void, Never>?
    private var isSceneActive: Bool = true

    init() {
        let loaded = VdpiAppGroup.loadSettings()
        self.settings = loaded
        self.engineVersion = VdpiNativeBridge.version()
        observeVpnStatus()
        Task {
            await loadOrCreateManager()
        }
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
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
        var next = settings
        mutate(&next)
        guard next != settings else { return }

        let onDemandChanged = next.onDemandEnabled != settings.onDemandEnabled
        settings = next
        VdpiAppGroup.saveSettings(next)

        if phase == .connected, let applied = appliedSettings {
            pendingReconnect = next.requiresTunnelReload(comparedTo: applied)
        } else {
            pendingReconnect = false
        }

        if onDemandChanged {
            Task {
                await syncOnDemandPreference()
            }
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
        errorMessage = nil
        phase = .connecting
        VdpiAppGroup.saveSettings(settings)

        Task {
            do {
                let manager = try await ensureConfiguredManager()
                appliedSettings = settings
                pendingReconnect = false
                try manager.connection.startVPNTunnel()
                triggerHaptic(.medium)
            } catch {
                phase = .error
                errorMessage = error.localizedDescription
                triggerHaptic(.rigid)
            }
        }
    }

    func disconnect() {
        errorMessage = nil
        pendingReconnect = false
        phase = .disconnecting
        vpnManager?.connection.stopVPNTunnel()
        triggerHaptic(.light)
    }

    func applyChangesLive() {
        VdpiAppGroup.saveSettings(settings)
        guard phase == .connected,
              let session = vpnManager?.connection as? NETunnelProviderSession
        else {
            connect()
            return
        }

        Task {
            let reply = await sendMessage(.reloadEngine, via: session)
            if let reply,
               let text = String(data: reply, encoding: .utf8),
               text.contains("\"ok\":true")
            {
                appliedSettings = settings
                pendingReconnect = false
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
                _ = await sendMessage(.clearCache, via: session)
                showToast("Cleared TLS & DNS caches")
                await fetchTelemetryOnce()
            }
        } else {
            VdpiNativeBridge.clearCache()
            showToast("Cleared local caches")
        }
    }

    func runDiagnostics() {
        guard !doctorState.running else { return }
        doctorState = DoctorUiState(running: true, report: nil, error: nil)
        let configJson = settings.toNativeConfigJSON()

        Task {
            if phase == .connected,
               let session = vpnManager?.connection as? NETunnelProviderSession,
               let data = await sendMessage(.runDoctor(configJson: configJson), via: session),
               let report = try? JSONDecoder().decode(DoctorReport.self, from: data)
            {
                doctorState = DoctorUiState(running: false, report: report, error: nil)
                return
            }

            let report = await Task.detached(priority: .userInitiated) {
                VdpiNativeBridge.runDoctor(configJson: configJson)
            }.value
            doctorState = DoctorUiState(running: false, report: report, error: nil)
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
            Task { @MainActor [weak self] in
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
                syncStatus(existing.connection.status)
                if existing.connection.status == .connected {
                    appliedSettings = settings
                }
            }
        } catch {
            // Simulator or unprovisioned builds without NetworkExtension entitlement stay in standby cleanly.
        }
    }

    private func ensureConfiguredManager() async throws -> NETunnelProviderManager {
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
        applyOnDemandRules(to: manager, enabled: settings.onDemandEnabled)

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        vpnManager = manager
        return manager
    }

    private func syncOnDemandPreference() async {
        guard let manager = vpnManager else { return }
        applyOnDemandRules(to: manager, enabled: settings.onDemandEnabled)
        try? await manager.saveToPreferences()
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

    private func syncStatus(_ status: NEVPNStatus) {
        switch status {
        case .connected:
            phase = .connected
            errorMessage = nil
            if appliedSettings == nil {
                appliedSettings = settings
            }
            if isSceneActive {
                startTelemetryPolling()
            }
        case .connecting, .reasserting:
            phase = .connecting
        case .disconnecting:
            phase = .disconnecting
            telemetryTask?.cancel()
            telemetryTask = nil
        case .disconnected, .invalid:
            phase = .disconnected
            pendingReconnect = false
            appliedSettings = nil
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
        guard let session = vpnManager?.connection as? NETunnelProviderSession else { return }
        guard let data = await sendMessage(.snapshot, via: session),
              let decoded = try? JSONDecoder().decode(TelemetrySnapshot.self, from: data)
        else { return }
        telemetry = decoded
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
        generator.impactOccurred()
    }
}
