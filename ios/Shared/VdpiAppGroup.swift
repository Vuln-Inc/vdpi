import Foundation

/// App Group identifier and IPC message codec shared between `VdpiApp` and `VdpiPacketTunnel`.
public enum VdpiAppGroup {
    public static let suiteName = "group.com.vulninc.vdpi"
    public static let extensionBundleId = "com.vulninc.vdpi.packet-tunnel"
    private static let settingsKey = "vdpi_settings_v1"
    private static let appliedConfigKey = "vdpi_applied_config_v1"

    public static var defaults: UserDefaults {
        UserDefaults(suiteName: suiteName) ?? .standard
    }

    public static func loadSettings(from storage: UserDefaults = defaults) -> VdpiSettings {
        guard let data = storage.data(forKey: settingsKey),
              let decoded = try? JSONDecoder().decode(VdpiSettings.self, from: data)
        else {
            return VdpiSettings()
        }
        return decoded
    }

    public static func saveSettings(_ settings: VdpiSettings, to storage: UserDefaults = defaults) {
        if let encoded = try? JSONEncoder().encode(settings) {
            storage.set(encoded, forKey: settingsKey)
        }
    }

    public static func loadAppliedConfig(from defaults: UserDefaults? = nil) -> NativeEngineConfig? {
        let storage = defaults ?? VdpiAppGroup.defaults
        guard let data = storage.data(forKey: appliedConfigKey),
              let decoded = try? JSONDecoder().decode(NativeEngineConfig.self, from: data)
        else {
            return nil
        }
        return decoded
    }

    public static func saveAppliedConfig(_ config: NativeEngineConfig?, to defaults: UserDefaults? = nil) {
        let storage = defaults ?? VdpiAppGroup.defaults
        guard let config else {
            storage.removeObject(forKey: appliedConfigKey)
            return
        }
        if let encoded = try? JSONEncoder().encode(config) {
            storage.set(encoded, forKey: appliedConfigKey)
        }
    }
}

/// JSON-encoded request payloads exchanged over `NETunnelProviderSession.sendProviderMessage`.
public enum ProviderMessage: Codable, Equatable, Sendable {
    case snapshot
    case clearCache
    case runDoctor(configJson: String)
    case reloadEngine

    public func encodeData() -> Data? {
        try? JSONEncoder().encode(self)
    }

    public static func decodeData(_ data: Data) -> ProviderMessage? {
        try? JSONDecoder().decode(ProviderMessage.self, from: data)
    }
}

/// JSON-encoded reply returned by `PacketTunnelProvider` for control IPC commands.
public struct ProviderCommandResponse: Codable, Equatable, Sendable {
    public var ok: Bool
    public var error: String?

    public init(ok: Bool, error: String? = nil) {
        self.ok = ok
        self.error = error
    }

    public func encodeData() -> Data? {
        try? JSONEncoder().encode(self)
    }

    public static func decodeData(_ data: Data) -> ProviderCommandResponse? {
        try? JSONDecoder().decode(ProviderCommandResponse.self, from: data)
    }
}
