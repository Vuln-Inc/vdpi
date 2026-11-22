import Foundation

public enum VdpiFormatters {
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
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: date)
    }

    public static func formatStageShort(stageNumber: UInt8, label: String) -> String {
        "S\(stageNumber) · \(label)"
    }

    /// Normalizes a user-entered bypass domain or wildcard (e.g. `*.example.com`).
    /// Returns `nil` for empty or malformed inputs.
    public static func normalizeBypassDomain(_ raw: String) -> String? {
        let trimmed = raw
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .replacingOccurrences(of: "https://", with: "")
            .replacingOccurrences(of: "http://", with: "")
            .split(separator: "/").first.map(String.init) ?? ""

        guard !trimmed.isEmpty, trimmed.count <= 253 else {
            return nil
        }

        let body = trimmed.hasPrefix("*.") ? String(trimmed.dropFirst(2)) : trimmed
        guard body.contains("."), !body.hasPrefix("."), !body.hasSuffix(".") else {
            return nil
        }

        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789.-")
        guard body.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            return nil
        }

        return trimmed
    }
}
