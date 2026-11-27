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
        formatStageLabel(stageLabel, language: .en)
    }

    public static func formatStageLabel(_ stageLabel: String, language: AppLanguage) -> String {
        let l10n = L10n.catalog(for: language)
        switch stageLabel {
        case "ComboMultiRecord":
            return l10n.stageCombo
        case "OobSniDesync":
            return l10n.stageOobSni
        case "MultiRecordOob":
            return l10n.stageMultiOob
        case "FineFragment":
            return l10n.stageFineFragment
        case "DeepRecordStorm":
            return l10n.stageDeepStorm
        case "SlowSniSlice":
            return l10n.stageSlowSni
        case "DirectPassthrough":
            return l10n.stagePassthrough
        default:
            return stageLabel
        }
    }

    public static func formatStageShort(stageNumber: UInt8, label: String) -> String {
        "S\(stageNumber) · \(label)"
    }

    /// Validates IPv4, IPv6, or HTTPS DoH endpoint strings (parity with Rust `parse_doh_url_validated`).
    public static func isValidDnsInput(_ raw: String) -> Bool {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= 253 else { return false }
        let lower = trimmed.lowercased()
        if lower.hasPrefix("https://") {
            return isValidDohUrl(trimmed)
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

    private static func isValidDohUrl(_ trimmed: String) -> Bool {
        let rest = trimmed.dropFirst("https://".count)
        guard !rest.isEmpty,
              !rest.utf8.contains(UInt8(ascii: "#")),
              !rest.contains(where: { $0.isWhitespace })
        else {
            return false
        }

        let authority: Substring
        let suffix: Substring
        if let cut = rest.firstIndex(where: { $0 == "/" || $0 == "?" }) {
            authority = rest[..<cut]
            suffix = rest[cut...]
        } else {
            authority = rest
            suffix = ""
        }

        guard !authority.isEmpty, !authority.utf8.contains(UInt8(ascii: "@")) else {
            return false
        }

        if authority.hasPrefix("[") {
            let afterOpen = authority.dropFirst()
            guard let closeIdx = afterOpen.firstIndex(of: "]") else {
                return false
            }
            let ipStr = String(afterOpen[..<closeIdx])
            var v6 = in6_addr()
            guard !ipStr.isEmpty,
                  inet_pton(AF_INET6, ipStr, &v6) == 1,
                  isAllowedDohIpv6(v6)
            else {
                return false
            }
            let tail = afterOpen[afterOpen.index(after: closeIdx)...]
            if !tail.isEmpty {
                guard tail.hasPrefix(":"), isValidDohPort(tail.dropFirst()) else {
                    return false
                }
            }
        } else {
            guard !authority.utf8.contains(UInt8(ascii: "[")),
                  !authority.utf8.contains(UInt8(ascii: "]"))
            else {
                return false
            }
            let colonCount = authority.reduce(0) { $0 + ($1 == ":" ? 1 : 0) }
            guard colonCount <= 1 else {
                return false
            }
            let hostRaw: Substring
            if let colonIdx = authority.firstIndex(of: ":") {
                hostRaw = authority[..<colonIdx]
                let portStr = authority[authority.index(after: colonIdx)...]
                guard isValidDohPort(portStr) else {
                    return false
                }
            } else {
                hostRaw = authority
            }
            guard !hostRaw.isEmpty else {
                return false
            }

            let hostString = String(hostRaw)
            var v4 = in_addr()
            if inet_pton(AF_INET, hostString, &v4) == 1 {
                guard isAllowedDohIpv4(v4) else {
                    return false
                }
            } else {
                guard isValidDohHostname(hostRaw) else {
                    return false
                }
            }
        }

        if !suffix.isEmpty, !isValidDohPathAndQuery(suffix) {
            return false
        }
        return true
    }

    private static func isAsciiDigit(_ b: UInt8) -> Bool {
        (0x30...0x39).contains(b)
    }

    private static func isAsciiAlpha(_ b: UInt8) -> Bool {
        (0x41...0x5A).contains(b) || (0x61...0x7A).contains(b)
    }

    private static func isAsciiAlphanumeric(_ b: UInt8) -> Bool {
        isAsciiDigit(b) || isAsciiAlpha(b)
    }

    private static func isAsciiHexDigit(_ b: UInt8) -> Bool {
        isAsciiDigit(b) || (0x41...0x46).contains(b) || (0x61...0x66).contains(b)
    }

    private static func isValidDohPort(_ portStr: Substring) -> Bool {
        guard !portStr.isEmpty,
              portStr.utf8.allSatisfy(isAsciiDigit),
              let port = UInt16(portStr),
              port > 0
        else {
            return false
        }
        return true
    }

    private static func isAllowedDohIpv4Octets(_ b0: UInt8, _ b1: UInt8, _ b2: UInt8, _ b3: UInt8) -> Bool {
        if b0 == 0 { return false } // 0.0.0.0/8 (unspecified / this network)
        if b0 == 127 { return false } // 127.0.0.0/8 (loopback)
        if b0 == 169 && b1 == 254 { return false } // 169.254.0.0/16 (link-local)
        if (b0 & 0xF0) == 0xE0 { return false } // 224.0.0.0/4 (multicast)
        if b0 == 255 && b1 == 255 && b2 == 255 && b3 == 255 { return false } // broadcast
        return true
    }

    private static func isAllowedDohIpv4(_ addr: in_addr) -> Bool {
        let (b0, b1, b2, b3) = withUnsafeBytes(of: addr.s_addr) { ($0[0], $0[1], $0[2], $0[3]) }
        return isAllowedDohIpv4Octets(b0, b1, b2, b3)
    }

    private static func isAllowedDohIpv6(_ addr: in6_addr) -> Bool {
        withUnsafeBytes(of: addr) { bytes in
            guard bytes.count == 16 else { return false }
            if bytes.allSatisfy({ $0 == 0 }) { return false } // :: (unspecified)
            if bytes[0..<15].allSatisfy({ $0 == 0 }) && bytes[15] == 1 { return false } // ::1 (loopback)
            if bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80 { return false } // fe80::/10 (link-local)
            if bytes[0] == 0xFF { return false } // ff00::/8 (multicast)
            let isV4Mapped = bytes[0..<10].allSatisfy({ $0 == 0 })
                && bytes[10] == 0xFF
                && bytes[11] == 0xFF
            if isV4Mapped {
                return isAllowedDohIpv4Octets(bytes[12], bytes[13], bytes[14], bytes[15])
            }
            return true
        }
    }

    private static func isValidDohHostname(_ raw: Substring) -> Bool {
        let stripped = raw.hasSuffix(".") ? raw.dropLast() : raw
        let lower = stripped.lowercased()
        guard !lower.isEmpty, lower.utf8.count <= 253 else {
            return false
        }
        let labels = lower.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2 else {
            return false
        }
        for label in labels {
            let utf8 = label.utf8
            guard (1...63).contains(utf8.count),
                  utf8.first != UInt8(ascii: "-"),
                  utf8.last != UInt8(ascii: "-"),
                  utf8.allSatisfy({ isAsciiAlphanumeric($0) || $0 == UInt8(ascii: "-") })
            else {
                return false
            }
        }
        guard let tld = labels.last, tld.utf8.contains(where: isAsciiAlpha) else {
            return false
        }
        return true
    }

    private static func isValidDohPathAndQuery(_ suffix: Substring) -> Bool {
        let bytes = Array(suffix.utf8)
        var i = 0
        while i < bytes.count {
            let b = bytes[i]
            if b == UInt8(ascii: "%") {
                guard i + 2 < bytes.count,
                      isAsciiHexDigit(bytes[i + 1]),
                      isAsciiHexDigit(bytes[i + 2])
                else {
                    return false
                }
                i += 3
                continue
            }
            let allowed = isAsciiAlphanumeric(b)
                || b == UInt8(ascii: "-") || b == UInt8(ascii: ".") || b == UInt8(ascii: "_")
                || b == UInt8(ascii: "~") || b == UInt8(ascii: "/") || b == UInt8(ascii: "?")
                || b == UInt8(ascii: ":") || b == UInt8(ascii: "@") || b == UInt8(ascii: "!")
                || b == UInt8(ascii: "$") || b == UInt8(ascii: "&") || b == UInt8(ascii: "'")
                || b == UInt8(ascii: "(") || b == UInt8(ascii: ")") || b == UInt8(ascii: "*")
                || b == UInt8(ascii: "+") || b == UInt8(ascii: ",") || b == UInt8(ascii: ";")
                || b == UInt8(ascii: "=")
            guard allowed else {
                return false
            }
            i += 1
        }
        return true
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
