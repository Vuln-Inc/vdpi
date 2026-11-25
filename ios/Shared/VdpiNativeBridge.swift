import Foundation
import VdpiCore

/// Safe Swift facade around the `VdpiCore` Rust C-ABI static library.
public enum VdpiNativeBridge {
    private static let maxErrorBufferBytes = 512
    private static let pushBatchChunkSize = 64

    private static func takeOwnedString(_ ptr: UnsafeMutablePointer<CChar>?) -> String? {
        guard let ptr else { return nil }
        defer { vdpi_ios_string_free(ptr) }
        return String(cString: ptr)
    }

    private static func decodeErrorBuffer(_ buffer: inout [CChar], fallback: String) -> String {
        guard !buffer.isEmpty else { return fallback }
        buffer[buffer.count - 1] = 0
        let message = buffer.withUnsafeBufferPointer { buf -> String in
            guard let base = buf.baseAddress else { return "" }
            return String(cString: base)
        }
        return message.isEmpty ? fallback : message
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

    /// Starts the high-speed direct-FD iOS TUN engine by transferring ownership of a `dup()`'d
    /// `utun` file descriptor (`tunFd`). Returns `nil` on success, or an error string on failure.
    public static func startWithFd(
        tunFd: Int32,
        configJSON: String
    ) -> String? {
        var errBuf = [CChar](repeating: 0, count: maxErrorBufferBytes)
        let rc: Int32 = configJSON.withCString { cConfig in
            errBuf.withUnsafeMutableBufferPointer { buf in
                vdpi_ios_start_fd(tunFd, cConfig, buf.baseAddress, buf.count)
            }
        }
        if rc == 0 {
            return nil
        }
        return decodeErrorBuffer(
            &errBuf,
            fallback: "Failed to start native engine in direct-FD mode (code \(rc))"
        )
    }

    /// Starts the fallback `NEPacketTunnelFlow` iOS TUN engine with batched outbound delivery.
    /// Returns `nil` on success, or an error string on failure.
    public static func startBatched(
        configJSON: String,
        writeBatchCallback: @escaping VdpiWritePacketsBatchFn,
        userCtx: UnsafeMutableRawPointer?
    ) -> String? {
        var errBuf = [CChar](repeating: 0, count: maxErrorBufferBytes)
        let rc: Int32 = configJSON.withCString { cConfig in
            errBuf.withUnsafeMutableBufferPointer { buf in
                vdpi_ios_start_batched(cConfig, writeBatchCallback, userCtx, buf.baseAddress, buf.count)
            }
        }
        if rc == 0 {
            return nil
        }
        return decodeErrorBuffer(
            &errBuf,
            fallback: "Failed to start native engine in batched mode (code \(rc))"
        )
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

    /// Pushes a batch of raw IPv4/IPv6 packets into the engine, returning the number of packets
    /// accepted. Intentionally omits `@discardableResult` so callers observe channel backpressure.
    public static func pushPackets(_ packets: [Data]) -> Int {
        guard !packets.isEmpty else { return 0 }
        let capacity = min(packets.count, pushBatchChunkSize)
        var ptrs: [UnsafePointer<UInt8>?] = []
        var lens: [Int] = []
        ptrs.reserveCapacity(capacity)
        lens.reserveCapacity(capacity)

        var totalAccepted = 0
        var chunkStart = packets.startIndex
        while chunkStart < packets.endIndex {
            let chunkEnd = packets.index(
                chunkStart,
                offsetBy: pushBatchChunkSize,
                limitedBy: packets.endIndex
            ) ?? packets.endIndex
            ptrs.removeAll(keepingCapacity: true)
            lens.removeAll(keepingCapacity: true)
            totalAccepted += pushChunk(
                packets[chunkStart..<chunkEnd],
                cursor: chunkStart,
                ptrs: &ptrs,
                lens: &lens
            )
            chunkStart = chunkEnd
        }
        return totalAccepted
    }

    private static func pushChunk(
        _ slice: ArraySlice<Data>,
        cursor: ArraySlice<Data>.Index,
        ptrs: inout [UnsafePointer<UInt8>?],
        lens: inout [Int]
    ) -> Int {
        if cursor == slice.endIndex {
            guard !ptrs.isEmpty else { return 0 }
            return ptrs.withUnsafeBufferPointer { ptrBuf in
                lens.withUnsafeBufferPointer { lenBuf in
                    guard let ptrBase = ptrBuf.baseAddress,
                          let lenBase = lenBuf.baseAddress
                    else {
                        return 0
                    }
                    return vdpi_ios_push_packets(ptrBase, lenBase, ptrBuf.count)
                }
            }
        }

        let next = slice.index(after: cursor)
        return slice[cursor].withUnsafeBytes { rawBuffer in
            if rawBuffer.count > 0,
               let base = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self)
            {
                ptrs.append(base)
                lens.append(rawBuffer.count)
            }
            return pushChunk(slice, cursor: next, ptrs: &ptrs, lens: &lens)
        }
    }

    /// Signals an uplink or route change (e.g. Wi-Fi <-> Cellular handoff or device wake) to
    /// drain and rebind stale UDP sockets and clear stale DNS entries without wiping learned
    /// adaptive TLS strategies.
    public static func notifyRouteChange() {
        vdpi_ios_notify_route_change()
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
        return (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "0.5.4"
    }
}
