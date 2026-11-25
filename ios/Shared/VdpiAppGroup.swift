import Foundation

/// App Group identifier and IPC message codec shared between `VdpiApp` and `VdpiPacketTunnel`.
public enum VdpiAppGroup {
    private static let defaultSuiteName = "group.com.vulninc.vdpi"
    private static let defaultExtensionBundleId = "com.vulninc.vdpi.packet-tunnel"
    private static let packetTunnelExtensionPoint = "com.apple.networkextension.packet-tunnel"

    /// Resolves the active App Group dynamically from the signed `embedded.mobileprovision`
    /// profile (so paid Apple Developer / Sideloadly / Feather re-signing under any custom
    /// Team ID or bundle ID works without editing Swift source), falling back to the default
    /// group for TrollStore and Simulator builds.
    public static let suiteName: String = resolveSuiteName()

    /// Resolves the embedded `VdpiPacketTunnel.appex` bundle identifier dynamically from
    /// `PlugIns/*.appex/Info.plist`, falling back to `<mainBundleId>.packet-tunnel` and
    /// finally the default bundle ID.
    public static let extensionBundleId: String = resolveExtensionBundleId()

    private static let settingsKey = "vdpi_settings_v1"
    private static let appliedConfigKey = "vdpi_applied_config_v1"

    public static func resolveSuiteName(bundle: Bundle = .main) -> String {
        if let profileURL = bundle.url(forResource: "embedded", withExtension: "mobileprovision"),
           let data = try? Data(contentsOf: profileURL),
           let group = extractAppGroupFromProvisioningProfile(data, bundle: bundle) {
            return group
        }
        return defaultSuiteName
    }

    public static func extractAppGroupFromProvisioningProfile(
        _ data: Data,
        bundle: Bundle = .main
    ) -> String? {
        let startMarker = Data("<plist".utf8)
        let endMarker = Data("</plist>".utf8)
        guard let startRange = data.range(of: startMarker),
              let endRange = data.range(of: endMarker, in: startRange.lowerBound..<data.endIndex)
        else {
            return nil
        }

        let plistData = data.subdata(in: startRange.lowerBound..<endRange.upperBound)
        guard let plist = try? PropertyListSerialization.propertyList(
            from: plistData,
            options: [],
            format: nil
        ) as? [String: Any],
              let entitlements = plist["Entitlements"] as? [String: Any],
              let groups = entitlements["com.apple.security.application-groups"] as? [String]
        else {
            return nil
        }

        let candidates = groups
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { group in
                group.hasPrefix("group.") && group.count > 6 && !group.contains("*")
            }
        guard !candidates.isEmpty else { return nil }

        let accessible = candidates.filter { group in
            FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) != nil
        }
        let pool = accessible.isEmpty ? candidates : accessible

        if let exact = pool.first(where: { $0 == defaultSuiteName }) {
            return exact
        }

        if let rawBundleId = bundle.bundleIdentifier?.trimmingCharacters(in: .whitespacesAndNewlines),
           !rawBundleId.isEmpty
        {
            let baseBundleId = rawBundleId
                .replacingOccurrences(of: ".packet-tunnel", with: "")
                .lowercased()
            if !baseBundleId.isEmpty,
               let bundleMatch = pool.first(where: { group in
                   let lowered = group.lowercased()
                   return lowered == "group.\(baseBundleId)" || lowered.hasSuffix(".\(baseBundleId)")
               })
            {
                return bundleMatch
            }
        }

        if let vdpiMatch = pool.first(where: { $0.lowercased().contains("vdpi") }) {
            return vdpiMatch
        }

        return pool.first
    }

    public static func resolveExtensionBundleId(bundle: Bundle = .main) -> String {
        if let plugInsURL = bundle.builtInPlugInsURL,
           let entries = try? FileManager.default.contentsOfDirectory(
               at: plugInsURL,
               includingPropertiesForKeys: nil,
               options: [.skipsHiddenFiles]
           ) {
            for entry in entries where entry.pathExtension.lowercased() == "appex" {
                let infoURL = entry.appendingPathComponent("Info.plist")
                guard let infoData = try? Data(contentsOf: infoURL),
                      let info = try? PropertyListSerialization.propertyList(
                          from: infoData,
                          options: [],
                          format: nil
                      ) as? [String: Any],
                      let nsExt = info["NSExtension"] as? [String: Any],
                      let point = nsExt["NSExtensionPointIdentifier"] as? String,
                      point == packetTunnelExtensionPoint,
                      let bundleId = info["CFBundleIdentifier"] as? String,
                      !bundleId.isEmpty
                else {
                    continue
                }
                return bundleId
            }
        }

        if let mainId = bundle.bundleIdentifier, !mainId.isEmpty {
            if mainId.contains(".packet-tunnel") {
                return mainId
            }
            return "\(mainId).packet-tunnel"
        }
        return defaultExtensionBundleId
    }

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
