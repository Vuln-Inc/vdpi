import Foundation

/// Mirrors `vdpi::config::DesyncMode` wire serialization exactly.
public enum DesyncMode: String, CaseIterable, Codable, Identifiable, Sendable {
    case combo = "combo"
    case tlsRecord = "tls-record"
    case fragment = "fragment"
    case split = "split"

    public var id: String { rawValue }

    public var label: String {
        switch self {
        case .combo: return "Combo"
        case .tlsRecord: return "TLS Record"
        case .fragment: return "Fragment"
        case .split: return "Split"
        }
    }

    public var subtitle: String {
        switch self {
        case .combo: return "4-record TLS split + adaptive 7-stage auto-heal"
        case .tlsRecord: return "Split ClientHello across two RFC TLS records"
        case .fragment: return "Single outer TLS record sliced at SNI boundaries"
        case .split: return "Initial chunk-byte TCP split on first flight"
        }
    }
}

public enum ThemePreference: String, CaseIterable, Codable, Identifiable, Sendable {
    case system = "system"
    case dark = "dark"
    case light = "light"

    public var id: String { rawValue }

    public var label: String {
        switch self {
        case .system: return "System"
        case .dark: return "Dark"
        case .light: return "Light"
        }
    }
}

/// Wire JSON passed into `vdpi_ios_start` / `vdpi_ios_run_doctor_json` (matches `vdpi_tun::config::TunnelConfig`).
public typealias VdpiTunnelConfig = NativeEngineConfig

public struct NativeEngineConfig: Codable, Equatable, Sendable {
    public var mode: DesyncMode
    public var chunkSize: Int
    public var dnsAddr: String
    public var enableDoh: Bool
    public var ipv4Only: Bool
    public var blockQuic: Bool
    public var timeoutMs: UInt64
    public var mtu: Int
    public var bypassDomains: [String]
    public var cachePath: String?

    enum CodingKeys: String, CodingKey {
        case mode
        case chunkSize = "chunk_size"
        case dnsAddr = "dns_addr"
        case enableDoh = "enable_doh"
        case ipv4Only = "ipv4_only"
        case blockQuic = "block_quic"
        case timeoutMs = "timeout_ms"
        case mtu
        case bypassDomains = "bypass_domains"
        case cachePath = "cache_path"
    }

    public init(
        mode: DesyncMode = .combo,
        chunkSize: Int = 10,
        dnsAddr: String = "1.1.1.1",
        enableDoh: Bool = true,
        ipv4Only: Bool = false,
        blockQuic: Bool = true,
        timeoutMs: UInt64 = 8000,
        mtu: Int = 4064,
        bypassDomains: [String] = [],
        cachePath: String? = nil
    ) {
        self.mode = mode
        self.chunkSize = max(1, min(64, chunkSize))
        let trimmedDns = dnsAddr.trimmingCharacters(in: .whitespacesAndNewlines)
        self.dnsAddr = trimmedDns.isEmpty ? "1.1.1.1" : trimmedDns
        self.enableDoh = enableDoh
        self.ipv4Only = ipv4Only
        self.blockQuic = blockQuic
        self.timeoutMs = timeoutMs
        self.mtu = max(1280, min(4064, mtu))
        self.bypassDomains = bypassDomains
        self.cachePath = cachePath
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let mode = try c.decodeIfPresent(DesyncMode.self, forKey: .mode) ?? .combo
        let chunkSize = try c.decodeIfPresent(Int.self, forKey: .chunkSize) ?? 10
        let dnsAddr = try c.decodeIfPresent(String.self, forKey: .dnsAddr) ?? "1.1.1.1"
        let enableDoh = try c.decodeIfPresent(Bool.self, forKey: .enableDoh) ?? true
        let ipv4Only = try c.decodeIfPresent(Bool.self, forKey: .ipv4Only) ?? false
        let blockQuic = try c.decodeIfPresent(Bool.self, forKey: .blockQuic) ?? true
        let timeoutMs = try c.decodeIfPresent(UInt64.self, forKey: .timeoutMs) ?? 8000
        let mtu = try c.decodeIfPresent(Int.self, forKey: .mtu) ?? 4064
        let bypassDomains = try c.decodeIfPresent([String].self, forKey: .bypassDomains) ?? []
        let cachePath = try c.decodeIfPresent(String.self, forKey: .cachePath)
        self.init(
            mode: mode,
            chunkSize: chunkSize,
            dnsAddr: dnsAddr,
            enableDoh: enableDoh,
            ipv4Only: ipv4Only,
            blockQuic: blockQuic,
            timeoutMs: timeoutMs,
            mtu: mtu,
            bypassDomains: bypassDomains,
            cachePath: cachePath
        )
    }

    public func canonicalized() -> NativeEngineConfig {
        NativeEngineConfig(
            mode: mode,
            chunkSize: chunkSize,
            dnsAddr: dnsAddr,
            enableDoh: enableDoh,
            ipv4Only: ipv4Only,
            blockQuic: blockQuic,
            timeoutMs: timeoutMs,
            mtu: mtu,
            bypassDomains: Self.canonicalBypassDomains(bypassDomains),
            cachePath: cachePath
        )
    }

    public static func canonicalBypassDomains(_ domains: [String]) -> [String] {
        var seen = Set<String>()
        var unique: [String] = []
        unique.reserveCapacity(domains.count)
        for raw in domains {
            let cleaned = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !cleaned.isEmpty else { continue }
            if seen.insert(cleaned).inserted {
                unique.append(cleaned)
            }
        }
        return unique.sorted()
    }
}

/// Persistent user settings shared between `VdpiApp` and `VdpiPacketTunnel` via App Group.
public struct VdpiSettings: Codable, Equatable, Sendable {
    /// Shared `providerConfiguration` / `startVPNTunnel(options:)` key used to deliver
    /// JSON-encoded `VdpiSettings` directly to `PacketTunnelProvider` even when App Group
    /// `UserDefaults` sharing is broken by third-party re-signers.
    public static let providerConfigSettingsKey = "vdpiSettingsJSON"

    public var desyncMode: DesyncMode
    public var chunkSize: Int
    public var dnsAddr: String
    public var enableDoh: Bool
    public var ipv4Only: Bool
    public var blockQuic: Bool
    public var mtu: Int
    public var bypassDomains: [String]
    public var onDemandEnabled: Bool
    public var theme: ThemePreference

    enum CodingKeys: String, CodingKey {
        case desyncMode
        case chunkSize
        case dnsAddr
        case enableDoh
        case ipv4Only
        case blockQuic
        case mtu
        case bypassDomains
        case onDemandEnabled
        case theme
    }

    public init(
        desyncMode: DesyncMode = .combo,
        chunkSize: Int = 10,
        dnsAddr: String = "1.1.1.1",
        enableDoh: Bool = true,
        ipv4Only: Bool = false,
        blockQuic: Bool = true,
        mtu: Int = 4064,
        bypassDomains: [String] = [],
        onDemandEnabled: Bool = false,
        theme: ThemePreference = .system
    ) {
        self.desyncMode = desyncMode
        self.chunkSize = max(1, min(64, chunkSize))
        self.dnsAddr = dnsAddr
        self.enableDoh = enableDoh
        self.ipv4Only = ipv4Only
        self.blockQuic = blockQuic
        self.mtu = max(1280, min(4064, mtu))
        self.bypassDomains = bypassDomains
        self.onDemandEnabled = onDemandEnabled
        self.theme = theme
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.desyncMode = try c.decodeIfPresent(DesyncMode.self, forKey: .desyncMode) ?? .combo
        let rawChunk = try c.decodeIfPresent(Int.self, forKey: .chunkSize) ?? 10
        self.chunkSize = max(1, min(64, rawChunk))
        self.dnsAddr = try c.decodeIfPresent(String.self, forKey: .dnsAddr) ?? "1.1.1.1"
        self.enableDoh = try c.decodeIfPresent(Bool.self, forKey: .enableDoh) ?? true
        self.ipv4Only = try c.decodeIfPresent(Bool.self, forKey: .ipv4Only) ?? false
        self.blockQuic = try c.decodeIfPresent(Bool.self, forKey: .blockQuic) ?? true
        let rawMtu = try c.decodeIfPresent(Int.self, forKey: .mtu) ?? 4064
        self.mtu = max(1280, min(4064, rawMtu))
        self.bypassDomains = try c.decodeIfPresent([String].self, forKey: .bypassDomains) ?? []
        self.onDemandEnabled = try c.decodeIfPresent(Bool.self, forKey: .onDemandEnabled) ?? false
        self.theme = try c.decodeIfPresent(ThemePreference.self, forKey: .theme) ?? .system
    }

    public var clampedChunkSize: Int {
        max(1, min(64, chunkSize))
    }

    public var clampedMtu: Int {
        max(1280, min(4064, mtu))
    }

    /// Compares only settings that require a tunnel restart/reload when changed.
    public func requiresTunnelReload(comparedTo other: VdpiSettings) -> Bool {
        requiresTunnelReload(comparedToApplied: other.toNativeConfig())
    }

    public func requiresTunnelReload(comparedToApplied config: NativeEngineConfig) -> Bool {
        !changedFieldLabels(comparedToApplied: config).isEmpty
    }

    public func changedFieldLabels(comparedTo other: VdpiSettings) -> [String] {
        changedFieldLabels(comparedToApplied: other.toNativeConfig())
    }

    public func changedFieldLabels(comparedToApplied config: NativeEngineConfig) -> [String] {
        let current = toNativeConfig()
        let applied = config.canonicalized()
        var labels: [String] = []
        if current.mode != applied.mode {
            labels.append("Mode")
        }
        if current.chunkSize != applied.chunkSize {
            labels.append("Chunk")
        }
        if current.dnsAddr != applied.dnsAddr {
            labels.append("DNS")
        }
        if current.enableDoh != applied.enableDoh {
            labels.append("DoH")
        }
        if current.ipv4Only != applied.ipv4Only {
            labels.append("IPv4")
        }
        if current.blockQuic != applied.blockQuic {
            labels.append("QUIC")
        }
        if current.mtu != applied.mtu {
            labels.append("MTU")
        }
        if current.bypassDomains != applied.bypassDomains {
            labels.append("Bypass")
        }
        return labels
    }

    /// Concise summary for the floating reconnect banner and Home inline reconnect card.
    public func pendingChangeSummary(comparedToApplied config: NativeEngineConfig) -> String {
        let labels = changedFieldLabels(comparedToApplied: config)
        guard !labels.isEmpty else { return "" }
        if labels.count <= 3 {
            return labels.joined(separator: ", ")
        }
        let head = labels.prefix(2).joined(separator: ", ")
        return "\(head) +\(labels.count - 2) more"
    }

    public func toNativeConfig(cachePath: String? = nil) -> NativeEngineConfig {
        NativeEngineConfig(
            mode: desyncMode,
            chunkSize: clampedChunkSize,
            dnsAddr: dnsAddr,
            enableDoh: enableDoh,
            ipv4Only: ipv4Only,
            blockQuic: blockQuic,
            timeoutMs: 8000,
            mtu: clampedMtu,
            bypassDomains: NativeEngineConfig.canonicalBypassDomains(bypassDomains),
            cachePath: cachePath
        )
    }

    public func toNativeConfigJSON(cachePath: String? = nil) -> String {
        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(toNativeConfig(cachePath: cachePath)),
              let json = String(data: data, encoding: .utf8)
        else {
            return "{}"
        }
        return json
    }
}

public struct EngineEvent: Codable, Equatable, Identifiable, Sendable {
    public var seq: UInt64?
    public var tsMs: UInt64
    public var level: String
    public var tag: String
    public var message: String

    public init(
        seq: UInt64? = nil,
        tsMs: UInt64,
        level: String,
        tag: String,
        message: String
    ) {
        self.seq = seq
        self.tsMs = tsMs
        self.level = level
        self.tag = tag
        self.message = message
    }

    public var id: String {
        if let seq {
            return "seq-\(seq)"
        }
        return "\(tsMs)-\(tag)-\(message.hashValue)"
    }

    enum CodingKeys: String, CodingKey {
        case seq
        case tsMs = "ts_ms"
        case level
        case tag
        case message
    }
}

public struct TelemetrySnapshot: Codable, Equatable, Sendable {
    public var running: Bool
    public var uptimeSecs: UInt64
    public var activeConnections: Int
    public var totalConnections: UInt64
    public var bytesTx: UInt64
    public var bytesRx: UInt64
    public var tlsHandshakes: UInt64
    public var autoHealEscalations: UInt64
    public var dnsQueries: UInt64
    public var quicBlocked: UInt64
    public var udpFlowsActive: UInt64
    public var learnedHosts: Int
    public var stageNumber: UInt8
    public var stageLabel: String
    public var dnsAddr: String
    public var dohEnabled: Bool
    public var events: [EngineEvent]

    enum CodingKeys: String, CodingKey {
        case running
        case uptimeSecs = "uptime_secs"
        case activeConnections = "active_connections"
        case totalConnections = "total_connections"
        case bytesTx = "bytes_tx"
        case bytesRx = "bytes_rx"
        case tlsHandshakes = "tls_handshakes"
        case autoHealEscalations = "auto_heal_escalations"
        case dnsQueries = "dns_queries"
        case quicBlocked = "quic_blocked"
        case udpFlowsActive = "udp_flows_active"
        case learnedHosts = "learned_hosts"
        case stageNumber = "stage_number"
        case stageLabel = "stage_label"
        case dnsAddr = "dns_addr"
        case dohEnabled = "doh_enabled"
        case events
    }

    public init(
        running: Bool,
        uptimeSecs: UInt64,
        activeConnections: Int,
        totalConnections: UInt64,
        bytesTx: UInt64,
        bytesRx: UInt64,
        tlsHandshakes: UInt64,
        autoHealEscalations: UInt64,
        dnsQueries: UInt64,
        quicBlocked: UInt64,
        udpFlowsActive: UInt64,
        learnedHosts: Int,
        stageNumber: UInt8,
        stageLabel: String,
        dnsAddr: String,
        dohEnabled: Bool,
        events: [EngineEvent]
    ) {
        self.running = running
        self.uptimeSecs = uptimeSecs
        self.activeConnections = activeConnections
        self.totalConnections = totalConnections
        self.bytesTx = bytesTx
        self.bytesRx = bytesRx
        self.tlsHandshakes = tlsHandshakes
        self.autoHealEscalations = autoHealEscalations
        self.dnsQueries = dnsQueries
        self.quicBlocked = quicBlocked
        self.udpFlowsActive = udpFlowsActive
        self.learnedHosts = learnedHosts
        self.stageNumber = stageNumber
        self.stageLabel = stageLabel
        self.dnsAddr = dnsAddr
        self.dohEnabled = dohEnabled
        self.events = events
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.running = try c.decodeIfPresent(Bool.self, forKey: .running) ?? false
        self.uptimeSecs = try c.decodeIfPresent(UInt64.self, forKey: .uptimeSecs) ?? 0
        self.activeConnections = try c.decodeIfPresent(Int.self, forKey: .activeConnections) ?? 0
        self.totalConnections = try c.decodeIfPresent(UInt64.self, forKey: .totalConnections) ?? 0
        self.bytesTx = try c.decodeIfPresent(UInt64.self, forKey: .bytesTx) ?? 0
        self.bytesRx = try c.decodeIfPresent(UInt64.self, forKey: .bytesRx) ?? 0
        self.tlsHandshakes = try c.decodeIfPresent(UInt64.self, forKey: .tlsHandshakes) ?? 0
        self.autoHealEscalations = try c.decodeIfPresent(UInt64.self, forKey: .autoHealEscalations) ?? 0
        self.dnsQueries = try c.decodeIfPresent(UInt64.self, forKey: .dnsQueries) ?? 0
        self.quicBlocked = try c.decodeIfPresent(UInt64.self, forKey: .quicBlocked) ?? 0
        self.udpFlowsActive = try c.decodeIfPresent(UInt64.self, forKey: .udpFlowsActive) ?? 0
        self.learnedHosts = try c.decodeIfPresent(Int.self, forKey: .learnedHosts) ?? 0
        self.stageNumber = try c.decodeIfPresent(UInt8.self, forKey: .stageNumber) ?? 1
        self.stageLabel = try c.decodeIfPresent(String.self, forKey: .stageLabel) ?? "ComboMultiRecord"
        self.dnsAddr = try c.decodeIfPresent(String.self, forKey: .dnsAddr) ?? "1.1.1.1"
        self.dohEnabled = try c.decodeIfPresent(Bool.self, forKey: .dohEnabled) ?? true
        self.events = try c.decodeIfPresent([EngineEvent].self, forKey: .events) ?? []
    }

    public static let idle = TelemetrySnapshot(
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
        dnsAddr: "1.1.1.1",
        dohEnabled: true,
        events: []
    )
}

public struct DoctorCheck: Codable, Equatable, Identifiable, Sendable {
    public var name: String
    public var target: String
    public var passed: Bool
    public var latencyMs: UInt64
    public var detail: String

    public init(
        name: String,
        target: String,
        passed: Bool,
        latencyMs: UInt64,
        detail: String
    ) {
        self.name = name
        self.target = target
        self.passed = passed
        self.latencyMs = latencyMs
        self.detail = detail
    }

    public var id: String { "\(name)-\(target)" }

    enum CodingKeys: String, CodingKey {
        case name
        case target
        case passed
        case latencyMs = "latency_ms"
        case detail
    }
}

public struct DoctorReport: Codable, Equatable, Sendable {
    public var ok: Bool
    public var checks: [DoctorCheck]

    public init(ok: Bool, checks: [DoctorCheck]) {
        self.ok = ok
        self.checks = checks
    }

    public static let empty = DoctorReport(ok: false, checks: [])
}
