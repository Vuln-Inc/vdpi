import Foundation

/// Metadata for an available GitHub release newer than the currently installed app version.
public struct VdpiUpdateInfo: Codable, Equatable, Sendable {
    public let latestVersion: String
    public let releaseURL: String
    public let releaseNotes: String

    public init(latestVersion: String, releaseURL: String, releaseNotes: String) {
        self.latestVersion = latestVersion
        self.releaseURL = releaseURL
        self.releaseNotes = releaseNotes
    }
}

/// Outcome of querying GitHub Releases for a newer version of `vdpi`.
public enum VdpiUpdateCheckResult: Equatable, Sendable {
    case updateAvailable(VdpiUpdateInfo)
    case upToDate
    case failed
}

/// Checks GitHub Releases for newer stable versions of `vdpi`.
public enum VdpiUpdateChecker {
    private static let latestReleaseEndpoint = "https://api.github.com/repos/Vuln-Inc/vdpi/releases/latest"
    private static let requestTimeout: TimeInterval = 10

    private struct GitHubReleaseResponse: Decodable {
        let tagName: String
        let htmlUrl: String
        let body: String?
        let draft: Bool?
        let prerelease: Bool?

        enum CodingKeys: String, CodingKey {
            case tagName = "tag_name"
            case htmlUrl = "html_url"
            case body
            case draft
            case prerelease
        }
    }

    /// Compares two strict semantic version strings (`vX.Y.Z` or `X.Y.Z`).
    /// Rejects prerelease tags, build metadata, missing/extra components, and non-numeric input.
    public static func isNewerVersion(_ latest: String, than current: String) -> Bool {
        guard let latestParts = parseStrictSemver(latest),
              let currentParts = parseStrictSemver(current)
        else {
            return false
        }
        return latestParts > currentParts
    }

    /// Queries the latest GitHub release and returns a typed result distinguishing
    /// available updates, up-to-date status, and network/validation failures.
    public static func fetchLatestReleaseResult(currentVersion: String) async -> VdpiUpdateCheckResult {
        guard let url = URL(string: latestReleaseEndpoint) else { return .failed }

        var request = URLRequest(
            url: url,
            cachePolicy: .reloadIgnoringLocalCacheData,
            timeoutInterval: requestTimeout
        )
        request.httpMethod = "GET"
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        let trimmedCurrent = currentVersion.trimmingCharacters(in: .whitespacesAndNewlines)
        let uaVersion = trimmedCurrent.isEmpty ? "unknown" : trimmedCurrent
        request.setValue("vdpi-ios/\(uaVersion)", forHTTPHeaderField: "User-Agent")

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse,
                  (200...299).contains(httpResponse.statusCode)
            else {
                return .failed
            }

            let release = try JSONDecoder().decode(GitHubReleaseResponse.self, from: data)
            if release.draft == true || release.prerelease == true {
                return .upToDate
            }

            let tag = release.tagName.trimmingCharacters(in: .whitespacesAndNewlines)
            let releaseURL = release.htmlUrl.trimmingCharacters(in: .whitespacesAndNewlines)
            guard isNewerVersion(tag, than: currentVersion) else {
                return .upToDate
            }
            guard let parsedURL = URL(string: releaseURL),
                  parsedURL.scheme?.lowercased() == "https",
                  parsedURL.host?.lowercased() == "github.com"
            else {
                return .failed
            }

            let normalizedVersion = stripLeadingV(tag)
            let notes = (release.body ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            return .updateAvailable(
                VdpiUpdateInfo(
                    latestVersion: normalizedVersion,
                    releaseURL: releaseURL,
                    releaseNotes: notes
                )
            )
        } catch {
            return .failed
        }
    }

    /// Queries the latest GitHub release and returns `VdpiUpdateInfo` only if it is strictly newer
    /// than `currentVersion`. Returns `nil` when up to date, offline, or on any decode/HTTP error.
    public static func fetchLatestRelease(currentVersion: String) async -> VdpiUpdateInfo? {
        if case .updateAvailable(let info) = await fetchLatestReleaseResult(currentVersion: currentVersion) {
            return info
        }
        return nil
    }

    private static func stripLeadingV(_ raw: String) -> String {
        guard let first = raw.first, first == "v" || first == "V" else {
            return raw
        }
        return String(raw.dropFirst())
    }

    private static func parseStrictSemver(_ raw: String) -> (UInt64, UInt64, UInt64)? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        let stripped = stripLeadingV(trimmed)
        guard !stripped.isEmpty, !stripped.contains("-"), !stripped.contains("+") else {
            return nil
        }

        let parts = stripped.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { return nil }

        guard let major = parseAsciiDigits(parts[0]),
              let minor = parseAsciiDigits(parts[1]),
              let patch = parseAsciiDigits(parts[2])
        else {
            return nil
        }

        return (major, minor, patch)
    }

    private static func parseAsciiDigits(_ component: Substring) -> UInt64? {
        guard !component.isEmpty,
              component.unicodeScalars.allSatisfy({ $0.value >= 48 && $0.value <= 57 })
        else {
            return nil
        }
        return UInt64(component)
    }
}
