import AppIntents
import Foundation
import NetworkExtension

// MARK: - App Intents (Siri Shortcuts & iOS Automations)

struct ConnectVdpiIntent: AppIntent {
    static let title: LocalizedStringResource = "Connect vdpi"
    static let description: IntentDescription? = IntentDescription("Starts the local vdpi anti-DPI tunnel.")
    static let openAppWhenRun: Bool = false

    func perform() async throws -> some IntentResult & ProvidesDialog {
        let dialog = try await VdpiTunnelIntentController.connect()
        return .result(dialog: IntentDialog(stringLiteral: dialog))
    }
}

struct DisconnectVdpiIntent: AppIntent {
    static let title: LocalizedStringResource = "Disconnect vdpi"
    static let description: IntentDescription? = IntentDescription("Stops the local vdpi anti-DPI tunnel.")
    static let openAppWhenRun: Bool = false

    func perform() async throws -> some IntentResult & ProvidesDialog {
        let dialog = try await VdpiTunnelIntentController.disconnect()
        return .result(dialog: IntentDialog(stringLiteral: dialog))
    }
}

struct ToggleVdpiIntent: AppIntent {
    static let title: LocalizedStringResource = "Toggle vdpi"
    static let description: IntentDescription? = IntentDescription("Turns the local vdpi anti-DPI tunnel on or off.")
    static let openAppWhenRun: Bool = false

    func perform() async throws -> some IntentResult & ProvidesDialog {
        let dialog = try await VdpiTunnelIntentController.toggle()
        return .result(dialog: IntentDialog(stringLiteral: dialog))
    }
}

struct VdpiShortcutsProvider: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: ConnectVdpiIntent(),
            phrases: [
                "Turn on \(.applicationName)",
                "Connect \(.applicationName)",
            ]
        )
        AppShortcut(
            intent: DisconnectVdpiIntent(),
            phrases: [
                "Turn off \(.applicationName)",
                "Disconnect \(.applicationName)",
            ]
        )
        AppShortcut(
            intent: ToggleVdpiIntent(),
            phrases: [
                "Toggle \(.applicationName)",
            ]
        )
    }
}

// MARK: - Background-Safe NetworkExtension Controller

private enum VdpiTunnelIntentController {
    static func connect() async throws -> String {
        let settings = VdpiAppGroup.loadSettings()
        let l10n = L10n.catalog(for: settings.language)

        let existingManagers = try await NETunnelProviderManager.loadAllFromPreferences()
        let existing = findManager(in: existingManagers)
        if let existing {
            let existingStatus = existing.connection.status
            if existingStatus == .connected || existingStatus == .connecting || existingStatus == .reasserting {
                return l10n.intentAlreadyConnected
            }
        }

        let manager = try await loadOrCreateManager(settings: settings, existingManager: existing)
        let status = manager.connection.status
        if status == .connected || status == .connecting || status == .reasserting {
            return l10n.intentAlreadyConnected
        }

        VdpiAppGroup.saveSettings(settings)
        VdpiAppGroup.saveAppliedConfig(settings.toNativeConfig())
        let startOptions: [String: NSObject]? = encodeSettingsJSON(settings).map {
            [providerConfigSettingsKey: $0 as NSObject]
        }
        do {
            try manager.connection.startVPNTunnel(options: startOptions)
        } catch {
            VdpiAppGroup.saveAppliedConfig(nil)
            throw error
        }
        return l10n.intentConnected
    }

    static func disconnect() async throws -> String {
        let l10n = L10n.catalog(for: VdpiAppGroup.loadSettings().language)
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        guard let manager = findManager(in: managers) else {
            VdpiAppGroup.saveAppliedConfig(nil)
            return l10n.intentAlreadyDisconnected
        }

        let status = manager.connection.status
        VdpiAppGroup.saveAppliedConfig(nil)
        if manager.isOnDemandEnabled {
            manager.isOnDemandEnabled = false
            manager.onDemandRules = nil
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
        }
        if status == .disconnected || status == .invalid {
            return l10n.intentAlreadyDisconnected
        }

        manager.connection.stopVPNTunnel()
        return l10n.intentDisconnected
    }

    static func toggle() async throws -> String {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        if let manager = findManager(in: managers) {
            switch manager.connection.status {
            case .connected, .connecting, .reasserting:
                return try await disconnect()
            case .disconnected, .disconnecting, .invalid:
                return try await connect()
            @unknown default:
                return try await connect()
            }
        }
        return try await connect()
    }

    private static let providerConfigSettingsKey = "vdpiSettingsJSON"

    private static func encodeSettingsJSON(_ settings: VdpiSettings) -> String? {
        guard let data = try? JSONEncoder().encode(settings) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    private static func findManager(
        in managers: [NETunnelProviderManager]
    ) -> NETunnelProviderManager? {
        managers.first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                == VdpiAppGroup.extensionBundleId
        }
    }

    private static func loadOrCreateManager(
        settings: VdpiSettings,
        existingManager: NETunnelProviderManager? = nil
    ) async throws -> NETunnelProviderManager {
        let manager: NETunnelProviderManager
        if let existingManager {
            manager = existingManager
        } else {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = findManager(in: managers) ?? NETunnelProviderManager()
        }

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = VdpiAppGroup.extensionBundleId
        proto.serverAddress = TunnelNetworkSettingsBuilder.tunnelRemoteAddress
        proto.includeAllNetworks = false
        proto.excludeLocalNetworks = true
        if #available(iOS 16.4, *) {
            proto.excludeAPNs = true
            proto.excludeCellularServices = true
        }
        if let settingsJSON = encodeSettingsJSON(settings) {
            proto.providerConfiguration = [providerConfigSettingsKey: settingsJSON]
        }

        manager.protocolConfiguration = proto
        manager.localizedDescription = "vdpi"
        manager.isEnabled = true
        manager.isOnDemandEnabled = settings.onDemandEnabled
        if settings.onDemandEnabled {
            let connectRule = NEOnDemandRuleConnect()
            connectRule.interfaceTypeMatch = .any
            manager.onDemandRules = [connectRule]
        } else {
            manager.onDemandRules = nil
        }

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        return manager
    }
}
