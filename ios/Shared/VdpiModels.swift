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
        case .combo: return "Adaptive 7-stage multi-record + OOB desync"
        case .tlsRecord: return "RFC-compliant multi-record ClientHello split"
        case .fragment: return "Paced single-record TCP fragmentation"
        case .split: return "Classic 2-segment SNI midpoint split"
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
    }

    public init(
        mode: DesyncMode = .combo,
        chunkSize: Int = 10,
        dnsAddr: String = "1.1.1.1",
        enableDoh: Bool = true,
        ipv4Only: Bool = false,
        blockQuic: Bool = true,
        timeoutMs: UInt64 = 8000,
        mtu: Int = 1500,
        bypassDomains: [String] = []
    ) {
        self.mode = mode
        self.chunkSize = max(1, min(64, chunkSize))
        let trimmedDns = dnsAddr.trimmingCharacters(in: .whitespacesAndNewlines)
        self.dnsAddr = trimmedDns.isEmpty ? "1.1.1.1" : trimmedDns
        self.enableDoh = enableDoh
        self.ipv4Only = ipv4Only
        self.blockQuic = blockQuic
        self.timeoutMs = timeoutMs
        self.mtu = max(1280, min(9000, mtu))
        self.bypassDomains = bypassDomains
    }
}

/// Persistent user settings shared between `VdpiApp` and `VdpiPacketTunnel` via App Group.
public struct VdpiSettings: Codable, Equatable, Sendable {
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

    public init(
        desyncMode: DesyncMode = .combo,
        chunkSize: Int = 10,
        dnsAddr: String = "1.1.1.1",
        enableDoh: Bool = true,
        ipv4Only: Bool = false,
        blockQuic: Bool = true,
        mtu: Int = 1500,
        bypassDomains: [String] = [],
        onDemandEnabled: Bool = false,
        theme: ThemePreference = .dark
    ) {
        self.desyncMode = desyncMode
        self.chunkSize = max(1, min(64, chunkSize))
        self.dnsAddr = dnsAddr
        self.enableDoh = enableDoh
        self.ipv4Only = ipv4Only
        self.blockQuic = blockQuic
        self.mtu = max(1280, min(9000, mtu))
        self.bypassDomains = bypassDomains
        self.onDemandEnabled = onDemandEnabled
        self.theme = theme
    }

    public var clampedMtu: Int {
        max(1280, min(9000, mtu))
    }

    /// Compares only settings that require a tunnel restart/reload when changed.
    public func requiresTunnelReload(comparedTo other: VdpiSettings) -> Bool {
        toNativeConfig() != other.toNativeConfig()
    }

    public func toNativeConfig() -> NativeEngineConfig {
        NativeEngineConfig(
            mode: desyncMode,
            chunkSize: chunkSize,
            dnsAddr: dnsAddr,
            enableDoh: enableDoh,
            ipv4Only: ipv4Only,
            blockQuic: blockQuic,
            timeoutMs: 8000,
            mtu: clampedMtu,
            bypassDomains: bypassDomains
        )
    }

    public func toNativeConfigJSON() -> String {
        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(toNativeConfig()),
              let json = String(data: data, encoding: .utf8)
        else {
            return "{}"
        }
        return json
    }
}

public struct EngineEvent: Codable, Equatable, Identifiable, Sendable {
    public var tsMs: UInt64
    public var level: String
    public var tag: String
    public var message: String

    public var id: String { "\(tsMs)-\(tag)-\(message.hashValue)" }

    enum CodingKeys: String, CodingKey {
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

    public static let empty = DoctorReport(ok: false, checks: [])
}
