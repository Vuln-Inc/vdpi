import Foundation
import VdpiCore

/// Safe Swift facade around the `VdpiCore` Rust C-ABI static library.
public enum VdpiNativeBridge {
    private static func takeOwnedString(_ ptr: UnsafeMutablePointer<CChar>?) -> String? {
        guard let ptr else { return nil }
        defer { vdpi_ios_string_free(ptr) }
        return String(cString: ptr)
    }

    /// Starts the iOS TUN engine. Returns `nil` on success, or an error string on failure.
    public static func start(
        configJson: String,
        writeCallback: @escaping VdpiWritePacketFn,
        userContext: UnsafeMutableRawPointer?
    ) -> String? {
        configJson.withCString { cConfig in
            takeOwnedString(vdpi_ios_start(cConfig, writeCallback, userContext))
        }
    }

    @discardableResult
    public static func pushPacket(_ data: Data) -> Bool {
        data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return false
            }
            return vdpi_ios_push_packet(base, rawBuffer.count)
        }
    }

    public static func stop() {
        vdpi_ios_stop()
    }

    public static func clearCache() {
        vdpi_ios_clear_cache()
    }

    public static func snapshotJson() -> String {
        takeOwnedString(vdpi_ios_snapshot_json()) ?? "{\"running\":false}"
    }

    public static func snapshot() -> TelemetrySnapshot {
        let json = snapshotJson()
        guard let data = json.data(using: .utf8),
              let decoded = try? JSONDecoder().decode(TelemetrySnapshot.self, from: data)
        else {
            return .idle
        }
        return decoded
    }

    public static func runDoctorJson(configJson: String) -> String {
        configJson.withCString { cConfig in
            takeOwnedString(vdpi_ios_run_doctor_json(cConfig)) ?? "{\"ok\":false,\"checks\":[]}"
        }
    }

    public static func runDoctor(configJson: String) -> DoctorReport {
        let json = runDoctorJson(configJson: configJson)
        guard let data = json.data(using: .utf8),
              let decoded = try? JSONDecoder().decode(DoctorReport.self, from: data)
        else {
            return .empty
        }
        return decoded
    }

    public static func version() -> String {
        if let native = takeOwnedString(vdpi_ios_version()), !native.isEmpty {
            return native
        }
        return (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "0.5.1"
    }
}
