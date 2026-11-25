import Darwin
import Foundation

public enum VdpiFormatters {
    private static let eventTimeLock = NSLock()
    private static let eventTimeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .autoupdatingCurrent
        formatter.dateFormat = "HH:mm:ss"
        return formatter
    }()

    public static func formatBytes(_ bytes: UInt64) -> String {
        if bytes < 1024 {
            return "\(bytes) B"
        }
        let kb = Double(bytes) / 1024.0
        if kb < 1024.0 {
            return String(format: "%.1f KB", locale: Locale(identifier: "en_US_POSIX"), kb)
        }
        let mb = kb / 1024.0
        if mb < 1024.0 {
            return String(format: "%.1f MB", locale: Locale(identifier: "en_US_POSIX"), mb)
        }
        let gb = mb / 1024.0
        return String(format: "%.2f GB", locale: Locale(identifier: "en_US_POSIX"), gb)
    }

    public static func formatUptime(_ seconds: UInt64) -> String {
        let hrs = seconds / 3600
        let mins = (seconds % 3600) / 60
        let secs = seconds % 60
        if hrs > 0 {
            return String(format: "%02llu:%02llu:%02llu", hrs, mins, secs)
        }
        return String(format: "%02llu:%02llu", mins, secs)
    }

    public static func formatEventTime(_ tsMs: UInt64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(tsMs) / 1000.0)
        eventTimeLock.lock()
        defer { eventTimeLock.unlock() }
        return eventTimeFormatter.string(from: date)
    }

    public static func formatStageLabel(_ stageLabel: String) -> String {
        switch stageLabel {
        case "ComboMultiRecord":
            return "Combo"
        case "OobSniDesync":
            return "OOB SNI"
        case "MultiRecordOob":
            return "Multi + OOB"
        case "FineFragment":
            return "Fine Fragment"
        case "DeepRecordStorm":
            return "Deep Storm"
        case "SlowSniSlice":
            return "Slow SNI"
        case "DirectPassthrough":
            return "Passthrough"
        default:
            return stageLabel
        }
    }

    public static func formatStageShort(stageNumber: UInt8, label: String) -> String {
        "S\(stageNumber) · \(label)"
    }

    /// Validates IPv4, IPv6, or HTTPS DoH endpoint strings (parity with Android Formatters).
    public static func isValidDnsInput(_ raw: String) -> Bool {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= 253 else { return false }
        let lower = trimmed.lowercased()
        if lower.hasPrefix("https://") {
            guard let url = URL(string: trimmed), let host = url.host, !host.isEmpty else {
                return false
            }
            return true
        }
        let bare = trimmed.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        var v4 = in_addr()
        if inet_pton(AF_INET, bare, &v4) == 1 {
            return true
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, bare, &v6) == 1 {
            return true
        }
        return false
    }

    /// Normalizes a user-entered bypass domain, wildcard (e.g. `*.example.com`),
    /// or IPv4/IPv6 CIDR range (e.g. `203.0.113.0/24`, `2001:db8::/32`).
    /// Returns `nil` for empty or malformed inputs.
    public static func normalizeBypassDomain(_ raw: String) -> String? {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let hasScheme: Bool
        if value.hasPrefix("https://") {
            value = String(value.dropFirst("https://".count))
            hasScheme = true
        } else if value.hasPrefix("http://") {
            value = String(value.dropFirst("http://".count))
            hasScheme = true
        } else {
            hasScheme = false
        }

        // Detect and preserve valid IPv4/IPv6 CIDR inputs (e.g. `203.0.113.0/24`, `2001:db8::/32`)
        // before URL path `/` stripping.
        if !hasScheme, value.contains("/") {
            let parts = value.split(separator: "/", omittingEmptySubsequences: false)
            let addrPart = String(parts[0])
            var v4 = in_addr()
            let isIpv4 = !addrPart.isEmpty && inet_pton(AF_INET, addrPart, &v4) == 1
            var v6 = in6_addr()
            let isIpv6 = !isIpv4 && !addrPart.isEmpty && inet_pton(AF_INET6, addrPart, &v6) == 1
            if isIpv4 || isIpv6 {
                guard parts.count == 2 else { return nil }
                let prefixPart = parts[1]
                guard !prefixPart.isEmpty,
                      prefixPart.allSatisfy({ $0.isASCII && $0.isNumber }),
                      let prefix = Int(prefixPart)
                else {
                    return nil
                }
                let maxPrefix = isIpv4 ? 32 : 128
                guard (0...maxPrefix).contains(prefix) else {
                    return nil
                }
                return "\(addrPart)/\(prefix)"
            }
        }

        if let cut = value.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) {
            value = String(value[..<cut])
        }
        if let colon = value.firstIndex(of: ":") {
            value = String(value[..<colon])
        }
        while value.hasSuffix(".") {
            value.removeLast()
        }

        guard !value.isEmpty, value.count <= 253 else {
            return nil
        }

        let isWildcard = value.hasPrefix("*.")
        let body = isWildcard ? String(value.dropFirst(2)) : value
        guard body.contains("."), !body.hasPrefix("."), !body.hasSuffix(".") else {
            return nil
        }

        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-")
        let labels = body.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2 else { return nil }
        for label in labels {
            guard (1...63).contains(label.count),
                  !label.hasPrefix("-"),
                  !label.hasSuffix("-"),
                  label.unicodeScalars.allSatisfy({ allowed.contains($0) })
            else {
                return nil
            }
        }

        return value
    }
}
