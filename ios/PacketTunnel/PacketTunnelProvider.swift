import Darwin
import Foundation
import Network
import NetworkExtension
import os
import VdpiCore

private let ipv4ProtocolNumber = NSNumber(value: AF_INET)
private let ipv6ProtocolNumber = NSNumber(value: AF_INET6)

private func vdpiOutboundBatchCallback(
    packets: UnsafePointer<VdpiPacketSlice>?,
    count: Int,
    userCtx: UnsafeMutableRawPointer?
) {
    // Runs on the dedicated Rust outbound writer thread (`vdpi-ios-tx`) with no RunLoop
    // autorelease pool: drain Objective-C bridged allocations immediately to stay well
    // under iOS's 50 MB NetworkExtension Jetsam ceiling.
    autoreleasepool {
        guard let packets, count > 0, let userCtx else { return }
        let provider = Unmanaged<PacketTunnelProvider>.fromOpaque(userCtx).takeUnretainedValue()
        let buffer = UnsafeBufferPointer(start: packets, count: count)
        var outPackets: [Data] = []
        var outProtocols: [NSNumber] = []
        outPackets.reserveCapacity(count)
        outProtocols.reserveCapacity(count)

        for slice in buffer {
            guard let ptr = slice.data, slice.len > 0 else { continue }
            outPackets.append(Data(bytes: ptr, count: slice.len))
            outProtocols.append(slice.family == 6 ? ipv6ProtocolNumber : ipv4ProtocolNumber)
        }

        guard !outPackets.isEmpty else { return }
        provider.writeOutboundPackets(outPackets, protocols: outProtocols)
    }
}

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private static let tunnelErrorDomain = "com.vulninc.vdpi.tunnel"
    private static let logger = Logger(subsystem: tunnelErrorDomain, category: "PacketTunnelProvider")
    private static let maxUtunScanFd: Int32 = 1024
    private static let maxInboundBatchChunkSize = 64
    private static let maxInboundBackpressureRetries = 8
    private static let inboundBackpressureRetryDelayMs = 2

    // Darwin kernel control constants (`<sys/kern_control.h>` / `<net/if_utun.h>` are not
    // exposed in the public iOS SDK, so define the stable XNU ABI values explicitly).
    private static let afSystem: UInt8 = 32
    private static let afSysControl: UInt16 = 2
    private static let sysprotoControl: Int32 = 2
    private static let utunOptIfname: Int32 = 2

    private static let ignoredPhysicalInterfacePrefixes: [String] = [
        "utun", "lo", "awdl", "llw", "ipsec", "anpi", "ap", "bridge",
    ]

    private let stateLock = NSLock()
    private var running = false
    private var stopping = false
    private var usingDirectUtunFd = false
    private var hasArmedPacketFlowRead = false
    private var inboundPumpArmed = false
    private var currentEffectiveIpv4Only: Bool?
    private var lastEffectiveSettings: VdpiSettings?
    private var lastProviderConfigJSON: String?
    private var lastPathSignature: String?
    private var defaultPathObservation: NSKeyValueObservation?
    private var networkPathMonitor: NWPathMonitor?
    private var latestNetworkPath: Network.NWPath?
    private var pathUpdateWorkItem: DispatchWorkItem?
    private var pathUpdateGeneration: UInt64 = 0
    private var reloadGeneration: UInt64 = 0

    private let lifecycleQueue = DispatchQueue(label: "com.vulninc.vdpi.tunnel.lifecycle", qos: .userInitiated)
    private let inboundPumpQueue = DispatchQueue(label: "com.vulninc.vdpi.tunnel.inbound", qos: .userInitiated)
    private let pathMonitorQueue = DispatchQueue(label: "com.vulninc.vdpi.tunnel.path", qos: .utility)
    private let doctorQueue = DispatchQueue(label: "com.vulninc.vdpi.tunnel.doctor", qos: .utility)

    deinit {
        isStopping = true
        isRunning = false
        stopPathMonitoring()
        VdpiNativeBridge.stop()
    }

    private var isRunning: Bool {
        get {
            stateLock.lock()
            defer { stateLock.unlock() }
            return running && !stopping
        }
        set {
            stateLock.lock()
            running = newValue
            stateLock.unlock()
        }
    }

    private var isStopping: Bool {
        get {
            stateLock.lock()
            defer { stateLock.unlock() }
            return stopping
        }
        set {
            stateLock.lock()
            stopping = newValue
            stateLock.unlock()
        }
    }

    private var isUsingDirectUtunFd: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return usingDirectUtunFd
    }

    private func setDirectUtunMode(_ enabled: Bool) {
        stateLock.lock()
        usingDirectUtunFd = enabled
        stateLock.unlock()
    }

    private func nextReloadGeneration() -> UInt64 {
        stateLock.lock()
        defer { stateLock.unlock() }
        reloadGeneration &+= 1
        return reloadGeneration
    }

    private func isCurrentReloadGeneration(_ generation: UInt64) -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return reloadGeneration == generation
    }

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        lifecycleQueue.async { [weak self] in
            guard let self else {
                completionHandler(NSError(
                    domain: Self.tunnelErrorDomain,
                    code: 1003,
                    userInfo: [NSLocalizedDescriptionKey: "Tunnel provider deallocated during startup"]
                ))
                return
            }

            self.isStopping = false
            self.stateLock.lock()
            self.usingDirectUtunFd = false
            self.hasArmedPacketFlowRead = false
            self.inboundPumpArmed = false
            self.stateLock.unlock()

            let settings = self.loadEffectiveSettings(options: options, overrideJSON: nil)
            let initialNetworkPath = self.currentPhysicalNetworkPath()
            let primaryIface = Self.resolvePrimaryPhysicalInterface(
                for: self.defaultPath,
                networkPath: initialNetworkPath
            )
            let effectiveIpv4Only = settings.ipv4Only
                || !TunnelNetworkSettingsBuilder.hasGlobalIpv6(onInterface: primaryIface)
            let effectiveMtu = TunnelNetworkSettingsBuilder.effectiveMtu(for: settings)
            let networkSettings = TunnelNetworkSettingsBuilder.build(
                settings: settings,
                effectiveIpv4Only: effectiveIpv4Only
            )

            self.setTunnelNetworkSettings(networkSettings) { [weak self] error in
                guard let self else {
                    completionHandler(error ?? NSError(
                        domain: Self.tunnelErrorDomain,
                        code: 1003,
                        userInfo: [NSLocalizedDescriptionKey: "Tunnel provider deallocated during startup"]
                    ))
                    return
                }
                self.lifecycleQueue.async {
                    if self.isStopping {
                        completionHandler(NSError(
                            domain: Self.tunnelErrorDomain,
                            code: 1002,
                            userInfo: [NSLocalizedDescriptionKey: "Tunnel stopped during startup"]
                        ))
                        return
                    }
                    if let error {
                        completionHandler(error)
                        return
                    }

                    let configJSON = Self.buildEngineConfigJSON(
                        from: settings,
                        effectiveIpv4Only: effectiveIpv4Only,
                        effectiveMtu: effectiveMtu
                    )
                    let startOutcome = self.startNativeEngine(configJSON: configJSON)
                    if let errMsg = startOutcome.error {
                        Self.logger.error(
                            "startTunnel failed to start native engine: \(errMsg, privacy: .public)"
                        )
                        completionHandler(NSError(
                            domain: Self.tunnelErrorDomain,
                            code: 1001,
                            userInfo: [NSLocalizedDescriptionKey: errMsg]
                        ))
                        return
                    }

                    if self.isStopping {
                        withExtendedLifetime(self) {
                            VdpiNativeBridge.stop()
                        }
                        completionHandler(NSError(
                            domain: Self.tunnelErrorDomain,
                            code: 1002,
                            userInfo: [NSLocalizedDescriptionKey: "Tunnel stopped during startup"]
                        ))
                        return
                    }

                    self.stateLock.lock()
                    self.currentEffectiveIpv4Only = effectiveIpv4Only
                    self.lastEffectiveSettings = settings
                    self.running = true
                    self.stateLock.unlock()

                    self.startPathMonitoring(initialNetworkPath: initialNetworkPath)
                    if !startOutcome.usedDirectFd {
                        self.ensureInboundPumpRunning()
                    }
                    let ioMode = startOutcome.usedDirectFd
                        ? "direct-utun (\(startOutcome.utunIfName ?? "utun"))"
                        : "packetFlow-fallback"
                    let ipv6Enabled = !effectiveIpv4Only
                    let ifaceName = primaryIface ?? "unknown"
                    Self.logger.notice(
                        "startTunnel active: mode=\(ioMode, privacy: .public) mtu=\(effectiveMtu, privacy: .public) ipv6Enabled=\(ipv6Enabled, privacy: .public) primaryIface=\(ifaceName, privacy: .public)"
                    )
                    VdpiAppGroup.saveAppliedConfig(settings.toNativeConfig())
                    completionHandler(nil)
                }
            }
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        isStopping = true
        isRunning = false
        stopPathMonitoring()
        // Execute teardown on lifecycleQueue so any in-flight start/reload finishes before
        // VdpiNativeBridge.stop() joins the Rust pipeline/writer and completionHandler returns.
        lifecycleQueue.async {
            self.stopPathMonitoring()
            withExtendedLifetime(self) {
                VdpiNativeBridge.stop()
            }
            self.stateLock.lock()
            self.usingDirectUtunFd = false
            self.hasArmedPacketFlowRead = false
            self.inboundPumpArmed = false
            self.currentEffectiveIpv4Only = nil
            self.stateLock.unlock()
            VdpiAppGroup.saveAppliedConfig(nil)
            completionHandler()
        }
    }

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        guard let message = ProviderMessage.decodeData(messageData) else {
            completionHandler?(nil)
            return
        }

        switch message {
        case .snapshot:
            let json = VdpiNativeBridge.snapshotJson()
            completionHandler?(json.data(using: .utf8))

        case .clearCache:
            lifecycleQueue.async {
                VdpiNativeBridge.clearCache()
                Self.removeAdaptiveCacheFile()
                completionHandler?(ProviderCommandResponse(ok: true).encodeData())
            }

        case .runDoctor(let configJson):
            // Run diagnostics on a dedicated queue so multi-second TLS probes never block reload/stop.
            doctorQueue.async {
                let reportJson = VdpiNativeBridge.runDoctorJson(configJson: configJson)
                completionHandler?(reportJson.data(using: .utf8))
            }

        case .reloadEngine:
            reloadTunnelEngine(overrideJSON: nil, completionHandler: completionHandler)

        case .reloadEngineWithSettings(let settingsJson):
            reloadTunnelEngine(overrideJSON: settingsJson, completionHandler: completionHandler)
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func wake() {
        lifecycleQueue.async { [weak self] in
            guard let self, self.isRunning else { return }
            VdpiNativeBridge.notifyRouteChange()
            self.evaluateDefaultPathChange(self.defaultPath, forceNotify: false)
        }
    }

    fileprivate func writeOutboundPackets(_ packets: [Data], protocols: [NSNumber]) {
        guard isRunning, !packets.isEmpty else { return }
        packetFlow.writePackets(packets, withProtocols: protocols)
    }

    // MARK: - Reload & Engine Start

    private func reloadTunnelEngine(
        overrideJSON: String?,
        completionHandler: ((Data?) -> Void)?
    ) {
        let generation = nextReloadGeneration()
        lifecycleQueue.async { [weak self] in
            guard let self else {
                completionHandler?(ProviderCommandResponse(ok: false, error: "Provider deallocated").encodeData())
                return
            }

            let finish: (ProviderCommandResponse) -> Void = { response in
                if self.isCurrentReloadGeneration(generation) {
                    self.reasserting = false
                }
                completionHandler?(response.encodeData())
            }

            guard self.isCurrentReloadGeneration(generation) else {
                completionHandler?(ProviderCommandResponse(ok: false, error: "Reload superseded").encodeData())
                return
            }
            guard self.isRunning else {
                finish(ProviderCommandResponse(ok: false, error: "Tunnel is not running"))
                return
            }

            let settings = self.loadEffectiveSettings(
                options: nil,
                overrideJSON: overrideJSON,
                preferAppGroupWhenProviderConfigUnchanged: true
            )
            let primaryIface = Self.resolvePrimaryPhysicalInterface(
                for: self.defaultPath,
                networkPath: self.currentPhysicalNetworkPath()
            )
            let effectiveIpv4Only = settings.ipv4Only
                || !TunnelNetworkSettingsBuilder.hasGlobalIpv6(onInterface: primaryIface)
            let effectiveMtu = TunnelNetworkSettingsBuilder.effectiveMtu(for: settings)
            let networkSettings = TunnelNetworkSettingsBuilder.build(
                settings: settings,
                effectiveIpv4Only: effectiveIpv4Only
            )

            self.reasserting = true
            self.setTunnelNetworkSettings(networkSettings) { [weak self] error in
                guard let self else {
                    completionHandler?(ProviderCommandResponse(ok: false, error: "Provider deallocated").encodeData())
                    return
                }
                self.lifecycleQueue.async {
                    guard self.isCurrentReloadGeneration(generation) else {
                        completionHandler?(ProviderCommandResponse(ok: false, error: "Reload superseded").encodeData())
                        return
                    }
                    guard self.isRunning else {
                        finish(ProviderCommandResponse(ok: false, error: "Tunnel stopped during reload"))
                        return
                    }
                    if let error {
                        finish(ProviderCommandResponse(ok: false, error: error.localizedDescription))
                        return
                    }

                    let configJSON = Self.buildEngineConfigJSON(
                        from: settings,
                        effectiveIpv4Only: effectiveIpv4Only,
                        effectiveMtu: effectiveMtu
                    )
                    let startOutcome = self.startNativeEngine(configJSON: configJSON)
                    if let errMsg = startOutcome.error {
                        Self.logger.error(
                            "reloadTunnelEngine failed to restart native engine: \(errMsg, privacy: .public)"
                        )
                        self.stopPathMonitoring()
                        self.stateLock.lock()
                        self.running = false
                        self.usingDirectUtunFd = false
                        self.hasArmedPacketFlowRead = false
                        self.inboundPumpArmed = false
                        self.currentEffectiveIpv4Only = nil
                        self.stateLock.unlock()
                        VdpiAppGroup.saveAppliedConfig(nil)
                        finish(ProviderCommandResponse(ok: false, error: errMsg))
                        self.cancelTunnelWithError(NSError(
                            domain: Self.tunnelErrorDomain,
                            code: 1004,
                            userInfo: [NSLocalizedDescriptionKey: errMsg]
                        ))
                        return
                    }

                    if !self.isRunning {
                        withExtendedLifetime(self) {
                            VdpiNativeBridge.stop()
                        }
                        finish(ProviderCommandResponse(ok: false, error: "Tunnel stopped during reload"))
                        return
                    }
                    guard self.isCurrentReloadGeneration(generation) else {
                        if !startOutcome.usedDirectFd {
                            self.ensureInboundPumpRunning()
                        }
                        completionHandler?(ProviderCommandResponse(ok: false, error: "Reload superseded").encodeData())
                        return
                    }

                    self.stateLock.lock()
                    self.currentEffectiveIpv4Only = effectiveIpv4Only
                    self.lastEffectiveSettings = settings
                    self.stateLock.unlock()

                    if !startOutcome.usedDirectFd {
                        self.ensureInboundPumpRunning()
                    }
                    let ioMode = startOutcome.usedDirectFd
                        ? "direct-utun (\(startOutcome.utunIfName ?? "utun"))"
                        : "packetFlow-fallback"
                    let ipv6Enabled = !effectiveIpv4Only
                    let ifaceName = primaryIface ?? "unknown"
                    Self.logger.notice(
                        "reloadTunnelEngine active: mode=\(ioMode, privacy: .public) mtu=\(effectiveMtu, privacy: .public) ipv6Enabled=\(ipv6Enabled, privacy: .public) primaryIface=\(ifaceName, privacy: .public)"
                    )
                    VdpiAppGroup.saveAppliedConfig(settings.toNativeConfig())
                    finish(ProviderCommandResponse(ok: true))
                }
            }
        }
    }

    /// Starts or restarts the native Rust engine, preferring direct `dup(utun_fd)` attachment
    /// and automatically falling back to batched `NEPacketTunnelFlow` I/O if no `utun` fd is
    /// available or direct-FD startup fails.
    private func startNativeEngine(
        configJSON: String
    ) -> (error: String?, usedDirectFd: Bool, utunIfName: String?) {
        stateLock.lock()
        let alreadyUsingPacketFlow = hasArmedPacketFlowRead
        stateLock.unlock()

        // Never race with an already-armed `packetFlow.readPackets` callback on reload.
        if !alreadyUsingPacketFlow {
            if let candidate = Self.duplicateTunnelFileDescriptor() {
                // Ownership of `candidate.fd >= 0` transfers immediately to `vdpi_ios_start_fd`
                // (`OwnedFd::from_raw_fd`), which closes it on stop or startup error.
                // Swift must never close `candidate.fd` once handed to `startWithFd`.
                if let fdError = VdpiNativeBridge.startWithFd(tunFd: candidate.fd, configJSON: configJSON) {
                    let ifName = candidate.ifName
                    let dupFd = candidate.fd
                    Self.logger.warning(
                        "Direct utun startup failed on \(ifName, privacy: .public) (dupFd=\(dupFd, privacy: .public)): \(fdError, privacy: .public); falling back to packetFlow"
                    )
                } else {
                    setDirectUtunMode(true)
                    return (nil, true, candidate.ifName)
                }
            } else {
                let scanLimit = Self.maxUtunScanFd
                Self.logger.info(
                    "No active utun fd found in 0..<\(scanLimit, privacy: .public); using packetFlow fallback"
                )
            }
        }

        let ctxPtr = Unmanaged.passUnretained(self).toOpaque()
        if let errMsg = VdpiNativeBridge.startBatched(
            configJSON: configJSON,
            writeBatchCallback: vdpiOutboundBatchCallback,
            userCtx: ctxPtr
        ) {
            return (errMsg, false, nil)
        }

        setDirectUtunMode(false)
        return (nil, false, nil)
    }

    // MARK: - Batched NEPacketTunnelFlow Fallback Pump

    private func ensureInboundPumpRunning() {
        stateLock.lock()
        guard running, !stopping, !usingDirectUtunFd else {
            stateLock.unlock()
            return
        }
        guard !inboundPumpArmed else {
            stateLock.unlock()
            return
        }
        inboundPumpArmed = true
        hasArmedPacketFlowRead = true
        stateLock.unlock()

        pumpInboundPackets()
    }

    private func pumpInboundPackets() {
        guard isRunning, !isUsingDirectUtunFd else {
            clearInboundPumpArmed()
            return
        }

        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            guard self.isRunning, !self.isUsingDirectUtunFd else {
                self.clearInboundPumpArmed()
                return
            }

            let validPackets = packets.filter { $0.count >= 20 && $0.count <= 65535 }
            guard !validPackets.isEmpty else {
                self.pumpInboundPackets()
                return
            }

            self.inboundPumpQueue.async { [weak self] in
                self?.pushInboundBatch(validPackets, offset: 0, retryCount: 0)
            }
        }
    }

    private func pushInboundBatch(_ packets: [Data], offset: Int, retryCount: Int) {
        guard isRunning, !isUsingDirectUtunFd else {
            clearInboundPumpArmed()
            return
        }

        var cursor = offset
        var retries = retryCount

        while cursor < packets.count {
            guard isRunning, !isUsingDirectUtunFd else {
                clearInboundPumpArmed()
                return
            }

            let chunkEnd = min(cursor + Self.maxInboundBatchChunkSize, packets.count)
            let batch: [Data] = (cursor == 0 && chunkEnd == packets.count)
                ? packets
                : Array(packets[cursor..<chunkEnd])

            let accepted = min(VdpiNativeBridge.pushPackets(batch), batch.count)
            cursor += accepted

            if accepted == batch.count {
                retries = 0
                continue
            }

            if retries < Self.maxInboundBackpressureRetries {
                let nextOffset = cursor
                let nextRetry = retries + 1
                inboundPumpQueue.asyncAfter(
                    deadline: .now() + .milliseconds(Self.inboundBackpressureRetryDelayMs)
                ) { [weak self] in
                    self?.pushInboundBatch(packets, offset: nextOffset, retryCount: nextRetry)
                }
                return
            }

            // Backpressure retry budget (8 * 2 ms) exhausted: resume reading so the pump never stalls.
            break
        }

        pumpInboundPackets()
    }

    private func clearInboundPumpArmed() {
        stateLock.lock()
        inboundPumpArmed = false
        stateLock.unlock()
    }

    // MARK: - Direct utun File Descriptor Discovery

    /// Scans POSIX fds `0..<1024` for the `NEPacketTunnelFlow` `utun` kernel control socket,
    /// prefers the interface holding `TunnelNetworkSettingsBuilder.tunnelIpv4Address` (`198.18.0.2`),
    /// picks the highest-numbered matching `utun*` fd (matching WireGuard/sing-box reconnect
    /// safety so stale/closing lower fds are never selected), duplicates it via `dup()`, and
    /// re-verifies the duplicated fd to guard against TOCTOU fd reuse.
    private static func duplicateTunnelFileDescriptor() -> (fd: Int32, ifName: String)? {
        var candidates: [(fd: Int32, ifName: String)] = []
        for fd in Int32(0)..<maxUtunScanFd {
            if let ifName = inspectUtunFd(fd) {
                candidates.append((fd: fd, ifName: ifName))
            }
        }
        guard !candidates.isEmpty else {
            return nil
        }

        let tunnelIfNames = interfaceNamesHoldingIpv4(TunnelNetworkSettingsBuilder.tunnelIpv4Address)
        let matchingTunnel = candidates.filter { tunnelIfNames.contains($0.ifName) }
        let orderedPool = matchingTunnel.isEmpty ? candidates : matchingTunnel
        // Prefer highest-numbered fd among matching candidates (orphan-utun guard).
        let sortedCandidates = orderedPool.sorted { $0.fd > $1.fd }

        for candidate in sortedCandidates {
            let dupFd = Darwin.dup(candidate.fd)
            guard dupFd >= 0 else { continue }
            // TOCTOU guard: verify the duplicated descriptor still refers to the same utun interface.
            if inspectUtunFd(dupFd) == candidate.ifName {
                return (fd: dupFd, ifName: candidate.ifName)
            }
            Darwin.close(dupFd)
        }
        return nil
    }

    /// Inspects `fd` using `getpeername` (`AF_SYSTEM` / `AF_SYS_CONTROL`) and
    /// `getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME)` to confirm it is an active `utun<N>`
    /// kernel control socket and return its interface name.
    ///
    /// Note: `ioctl(CTLIOCGINFO)` is intentionally not called from pure Swift because the iOS SDK
    /// omits `<sys/kern_control.h>` and Swift cannot safely invoke C variadic `ioctl` under the
    /// Apple arm64 ABI; combining `AF_SYSTEM`/`AF_SYS_CONTROL` peer verification, `UTUN_OPT_IFNAME`,
    /// `getifaddrs()` `198.18.0.2` matching, and post-`dup()` TOCTOU verification uniquely identifies
    /// the active `utun` descriptor.
    private static func inspectUtunFd(_ fd: Int32) -> String? {
        var storage = sockaddr_storage()
        var addrLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let peerResult: Int32 = withUnsafeMutablePointer(to: &storage) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.getpeername(fd, saPtr, &addrLen)
            }
        }
        // struct sockaddr_ctl layout:
        //   0: sc_len (u_char, 32)
        //   1: sc_family (u_char, AF_SYSTEM = 32)
        //   2..3: ss_sysaddr (u_int16_t, AF_SYS_CONTROL = 2)
        //   4..7: sc_id (u_int32_t, non-zero kernel control identifier)
        //   8..11: sc_unit (u_int32_t, 1-based utun unit)
        guard peerResult == 0, addrLen >= 12 else {
            return nil
        }

        let (scFamily, ssSysaddr, scId): (UInt8, UInt16, UInt32) = withUnsafeBytes(of: storage) { bytes in
            let family = bytes[1]
            let sysaddr = UInt16(bytes[2]) | (UInt16(bytes[3]) << 8)
            let id = UInt32(bytes[4])
                | (UInt32(bytes[5]) << 8)
                | (UInt32(bytes[6]) << 16)
                | (UInt32(bytes[7]) << 24)
            return (family, sysaddr, id)
        }
        guard scFamily == afSystem, ssSysaddr == afSysControl, scId != 0 else {
            return nil
        }

        var ifnameBuf = [CChar](repeating: 0, count: 32)
        var ifnameLen = socklen_t(ifnameBuf.count)
        let optResult: Int32 = ifnameBuf.withUnsafeMutableBytes { rawBuf in
            guard let base = rawBuf.baseAddress else { return -1 }
            return Darwin.getsockopt(
                fd,
                sysprotoControl,
                utunOptIfname,
                base,
                &ifnameLen
            )
        }
        guard optResult == 0, ifnameLen > 0, Int(ifnameLen) <= ifnameBuf.count else {
            return nil
        }
        ifnameBuf[min(Int(ifnameLen), ifnameBuf.count - 1)] = 0

        let ifName = String(cString: ifnameBuf)
        guard ifName.hasPrefix("utun") else {
            return nil
        }
        let suffix = ifName.dropFirst(4)
        guard !suffix.isEmpty, suffix.allSatisfy({ $0.isASCII && $0.isNumber }) else {
            return nil
        }
        return ifName
    }

    private static func interfaceNamesHoldingIpv4(_ targetAddress: String) -> Set<String> {
        var matched = Set<String>()
        var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrPtr) == 0, let first = ifaddrPtr else {
            return matched
        }
        defer { freeifaddrs(first) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            defer { cursor = current.pointee.ifa_next }
            guard let namePtr = current.pointee.ifa_name,
                  let addr = current.pointee.ifa_addr,
                  addr.pointee.sa_family == UInt8(AF_INET)
            else { continue }

            var sin = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            var ipBuf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            if inet_ntop(AF_INET, &sin.sin_addr, &ipBuf, socklen_t(INET_ADDRSTRLEN)) != nil,
               String(cString: ipBuf) == targetAddress
            {
                matched.insert(String(cString: namePtr))
            }
        }
        return matched
    }

    // MARK: - Active Physical Interface & defaultPath KVO Monitoring

    private func startPathMonitoring(initialNetworkPath: Network.NWPath? = nil) {
        stopPathMonitoring()

        let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other])
        monitor.pathUpdateHandler = { [weak self] networkPath in
            guard let self else { return }
            self.stateLock.lock()
            self.latestNetworkPath = networkPath
            self.stateLock.unlock()
            self.handleDefaultPathChange(self.defaultPath)
        }

        let initialPath = defaultPath
        let resolvedNetworkPath = initialNetworkPath ?? currentPhysicalNetworkPath()
        let initialSignature: String? = (initialPath?.status == .satisfied)
            ? Self.pathSignature(for: initialPath, networkPath: resolvedNetworkPath)
            : nil
        let observation = observe(\.defaultPath, options: [.new]) { [weak self] provider, _ in
            self?.handleDefaultPathChange(provider.defaultPath)
        }

        stateLock.lock()
        latestNetworkPath = resolvedNetworkPath
        lastPathSignature = initialSignature
        networkPathMonitor = monitor
        defaultPathObservation = observation
        stateLock.unlock()

        monitor.start(queue: pathMonitorQueue)
    }

    private func stopPathMonitoring() {
        stateLock.lock()
        let observation = defaultPathObservation
        let monitor = networkPathMonitor
        let pending = pathUpdateWorkItem
        defaultPathObservation = nil
        networkPathMonitor = nil
        latestNetworkPath = nil
        pathUpdateWorkItem = nil
        pathUpdateGeneration &+= 1
        lastPathSignature = nil
        stateLock.unlock()

        pending?.cancel()
        observation?.invalidate()
        monitor?.pathUpdateHandler = nil
        monitor?.cancel()
    }

    private func cachedNetworkPath() -> Network.NWPath? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return latestNetworkPath
    }

    private func currentPhysicalNetworkPath() -> Network.NWPath? {
        if let cached = cachedNetworkPath() {
            return cached
        }

        let probe = NWPathMonitor(prohibitedInterfaceTypes: [.other])
        let probeLock = NSLock()
        let semaphore = DispatchSemaphore(value: 0)
        var resolved: Network.NWPath?
        var finished = false

        probe.pathUpdateHandler = { path in
            probeLock.lock()
            let shouldSignal = !finished
            if shouldSignal {
                finished = true
                resolved = path
            }
            probeLock.unlock()
            if shouldSignal {
                probe.pathUpdateHandler = nil
                probe.cancel()
                semaphore.signal()
            }
        }
        probe.start(queue: pathMonitorQueue)
        _ = semaphore.wait(timeout: .now() + .milliseconds(100))

        probeLock.lock()
        let didFinish = finished
        finished = true
        let result = resolved
        probeLock.unlock()
        if !didFinish {
            probe.pathUpdateHandler = nil
            probe.cancel()
        }
        return result
    }

    private func handleDefaultPathChange(_ path: NetworkExtension.NWPath?) {
        guard isRunning else { return }
        evaluateDefaultPathChange(path, forceNotify: false)
    }

    private func evaluateDefaultPathChange(_ path: NetworkExtension.NWPath?, forceNotify: Bool) {
        guard isRunning else { return }
        guard let path, path.status == .satisfied else {
            stateLock.lock()
            let pending = pathUpdateWorkItem
            pathUpdateWorkItem = nil
            pathUpdateGeneration &+= 1
            lastPathSignature = nil
            stateLock.unlock()
            pending?.cancel()
            return
        }
        let signature = Self.pathSignature(for: path, networkPath: cachedNetworkPath())

        stateLock.lock()
        if !forceNotify && lastPathSignature == signature {
            let pending = pathUpdateWorkItem
            pathUpdateWorkItem = nil
            pathUpdateGeneration &+= 1
            stateLock.unlock()
            pending?.cancel()
            return
        }

        let previousPending = pathUpdateWorkItem
        pathUpdateGeneration &+= 1
        let generation = pathUpdateGeneration

        let workItem = DispatchWorkItem { [weak self] in
            guard let self, self.isRunning else { return }
            let latestPath = self.defaultPath
            guard let latestPath, latestPath.status == .satisfied else { return }
            let currentNetworkPath = self.cachedNetworkPath()
            let latestSignature = Self.pathSignature(for: latestPath, networkPath: currentNetworkPath)

            self.stateLock.lock()
            guard self.pathUpdateGeneration == generation else {
                self.stateLock.unlock()
                return
            }
            self.pathUpdateWorkItem = nil
            let previous = self.lastPathSignature
            self.lastPathSignature = latestSignature
            let previousIpv4Only = self.currentEffectiveIpv4Only
            let activeSettings = self.lastEffectiveSettings
            self.stateLock.unlock()

            guard forceNotify || previous != latestSignature else { return }

            // Immediately drain stale UDP Cone-NAT sockets and DNS entries without wiping
            // learned adaptive TLS strategies.
            VdpiNativeBridge.notifyRouteChange()

            let settings = activeSettings ?? self.loadEffectiveSettings(options: nil, overrideJSON: nil)
            let primaryIface = Self.resolvePrimaryPhysicalInterface(
                for: latestPath,
                networkPath: currentNetworkPath
            )
            let newEffectiveIpv4Only = settings.ipv4Only
                || !TunnelNetworkSettingsBuilder.hasGlobalIpv6(onInterface: primaryIface)

            if let previousIpv4Only, previousIpv4Only != newEffectiveIpv4Only {
                let preservedJSON = activeSettings.flatMap { try? JSONEncoder().encode($0) }
                    .flatMap { String(data: $0, encoding: .utf8) }
                self.reloadTunnelEngine(overrideJSON: preservedJSON, completionHandler: nil)
            }
        }
        pathUpdateWorkItem = workItem
        stateLock.unlock()

        previousPending?.cancel()
        lifecycleQueue.asyncAfter(deadline: .now() + .milliseconds(300), execute: workItem)
    }

    private static func pathSignature(
        for path: NetworkExtension.NWPath?,
        networkPath: Network.NWPath?
    ) -> String {
        guard let path else { return "none" }
        let snapshot = activePhysicalInterfacesSnapshot()
        let primaryIface = selectPrimaryInterface(from: snapshot, path: path, networkPath: networkPath)
        // Exclude volatile IPv6 temporary privacy addresses (RFC 4941) from the path signature
        // so routine IPv6 address churn does not tear down active UDP Cone-NAT flows.
        let primaryIpv4s = primaryIface
            .flatMap { snapshot.addressesByName[$0] }
            .map { $0.filter { !$0.contains(":") }.sorted().joined(separator: "|") }
            ?? ""
        let hasV6 = TunnelNetworkSettingsBuilder.hasGlobalIpv6(onInterface: primaryIface)
        return "\(path.status.rawValue):exp=\(path.isExpensive):con=\(path.isConstrained):if=\(primaryIface ?? "none"):v4=\(primaryIpv4s):v6=\(hasV6)"
    }

    private static func resolvePrimaryPhysicalInterface(
        for path: NetworkExtension.NWPath?,
        networkPath: Network.NWPath?
    ) -> String? {
        let snapshot = activePhysicalInterfacesSnapshot()
        return selectPrimaryInterface(from: snapshot, path: path, networkPath: networkPath)
    }

    private struct PhysicalInterfacesSnapshot {
        var enInterfaces: [String]
        var cellularInterfaces: [String]
        var otherInterfaces: [String]
        var addressesByName: [String: Set<String>]
    }

    private static func selectPrimaryInterface(
        from snapshot: PhysicalInterfacesSnapshot,
        path: NetworkExtension.NWPath?,
        networkPath: Network.NWPath?
    ) -> String? {
        if let path {
            guard path.status == .satisfied else {
                return nil
            }
        }
        if let networkPath, networkPath.status == .satisfied {
            func firstAvailable(where predicate: (NWInterface) -> Bool) -> String? {
                networkPath.availableInterfaces.first { iface in
                    snapshot.addressesByName[iface.name] != nil && predicate(iface)
                }?.name
            }

            // Prefer `networkPath.availableInterfaces` order over lexicographic `en*`/`pdp_ip*`
            // sorting so iPadOS USB-C Ethernet (e.g. `en3` over `en0`) and Dual-SIM/eSIM
            // (e.g. `pdp_ip1` over `pdp_ip0`) select the true active interface.
            // Check Wi-Fi / wired Ethernet BEFORE `isExpensive` so an IPv4-only Personal Hotspot
            // or Low Data Mode Wi-Fi (`en0` with `isExpensive == true`) never selects standby
            // cellular `pdp_ip*` IPv6 and blackholes dual-stack traffic.
            if networkPath.usesInterfaceType(.wifi) || networkPath.usesInterfaceType(.wiredEthernet) {
                return firstAvailable(where: {
                    ($0.type == .wiredEthernet || $0.type == .wifi)
                        && networkPath.usesInterfaceType($0.type)
                })
                    ?? firstAvailable(where: { $0.type == .wiredEthernet || $0.type == .wifi })
                    ?? firstAvailable(where: { snapshot.enInterfaces.contains($0.name) })
                    ?? firstAvailable(where: { snapshot.otherInterfaces.contains($0.name) })
                    ?? snapshot.enInterfaces.first
                    ?? snapshot.otherInterfaces.first
                    ?? snapshot.cellularInterfaces.first
            }
            if networkPath.usesInterfaceType(.cellular) || networkPath.isExpensive {
                return firstAvailable(where: { $0.type == .cellular })
                    ?? firstAvailable(where: { snapshot.cellularInterfaces.contains($0.name) })
                    ?? snapshot.cellularInterfaces.first
                    ?? firstAvailable(where: { snapshot.enInterfaces.contains($0.name) })
                    ?? snapshot.enInterfaces.first
                    ?? snapshot.otherInterfaces.first
            }
            if let preferred = firstAvailable(where: { _ in true }) {
                return preferred
            }
        }
        return snapshot.enInterfaces.first
            ?? snapshot.otherInterfaces.first
            ?? snapshot.cellularInterfaces.first
    }

    private static func activePhysicalInterfacesSnapshot() -> PhysicalInterfacesSnapshot {
        var enSet = Set<String>()
        var cellSet = Set<String>()
        var otherSet = Set<String>()
        var addressesByName: [String: Set<String>] = [:]

        var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrPtr) == 0, let first = ifaddrPtr else {
            return PhysicalInterfacesSnapshot(
                enInterfaces: [],
                cellularInterfaces: [],
                otherInterfaces: [],
                addressesByName: [:]
            )
        }
        defer { freeifaddrs(first) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            defer { cursor = current.pointee.ifa_next }
            let flags = Int32(bitPattern: current.pointee.ifa_flags)
            guard (flags & IFF_UP) != 0,
                  (flags & IFF_RUNNING) != 0,
                  (flags & IFF_LOOPBACK) == 0
            else { continue }
            guard let namePtr = current.pointee.ifa_name,
                  let addr = current.pointee.ifa_addr
            else { continue }

            let name = String(cString: namePtr)
            if ignoredPhysicalInterfacePrefixes.contains(where: { name.hasPrefix($0) }) {
                continue
            }

            let ipString: String?
            if isRoutableIpv4(addr) {
                var sin = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                ipString = inet_ntop(AF_INET, &sin.sin_addr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil
                    ? String(cString: buf)
                    : nil
            } else if isGlobalUnicastIpv6(addr) {
                var sin6 = addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                ipString = inet_ntop(AF_INET6, &sin6.sin6_addr, &buf, socklen_t(INET6_ADDRSTRLEN)) != nil
                    ? String(cString: buf)
                    : nil
            } else {
                continue
            }

            if let ipString {
                addressesByName[name, default: []].insert(ipString)
            }
            if name.hasPrefix("en") {
                enSet.insert(name)
            } else if name.hasPrefix("pdp_ip") {
                cellSet.insert(name)
            } else {
                otherSet.insert(name)
            }
        }

        let sortInterfaceNames: (String, String) -> Bool = { lhs, rhs in
            lhs.localizedStandardCompare(rhs) == .orderedAscending
        }
        return PhysicalInterfacesSnapshot(
            enInterfaces: enSet.sorted(by: sortInterfaceNames),
            cellularInterfaces: cellSet.sorted(by: sortInterfaceNames),
            otherInterfaces: otherSet.sorted(by: sortInterfaceNames),
            addressesByName: addressesByName
        )
    }

    private static func isRoutableIpv4(_ addr: UnsafePointer<sockaddr>) -> Bool {
        guard addr.pointee.sa_family == UInt8(AF_INET) else { return false }
        let sin = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
        let (first, second) = withUnsafeBytes(of: sin.sin_addr) { ($0[0], $0[1]) }
        if first == 0 || first == 127 || (first == 169 && second == 254) {
            return false
        }
        return true
    }

    private static func isGlobalUnicastIpv6(_ addr: UnsafePointer<sockaddr>) -> Bool {
        guard addr.pointee.sa_family == UInt8(AF_INET6) else { return false }
        let sin6 = addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
        let firstByte = withUnsafeBytes(of: sin6.sin6_addr) { $0[0] }
        return (firstByte & 0xE0) == 0x20
    }

    // MARK: - 3-Tier Sideloadly-Proof Settings & Cache Path

    /// Loads effective settings across 3 tiers so third-party re-signers (e.g. Sideloadly)
    /// that break App Group UserDefaults sharing never silently drop user settings back to defaults:
    ///   1. Explicit `overrideJSON` (IPC reload) or `options?[providerConfigSettingsKey]`
    ///   2. `(protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?[providerConfigSettingsKey]`
    ///   3. `VdpiAppGroup.loadSettings()`
    private func loadEffectiveSettings(
        options: [String: NSObject]?,
        overrideJSON: String?,
        preferAppGroupWhenProviderConfigUnchanged: Bool = false
    ) -> VdpiSettings {
        let appGroupWritable = Self.isAppGroupContainerWritable()

        // Tier 1: Explicit IPC override or `startVPNTunnel(options:)` payload.
        if let overrideJSON, let decoded = Self.decodeSettings(from: overrideJSON) {
            persistIfWritable(decoded, appGroupWritable: appGroupWritable)
            cacheLoadedSettings(decoded, providerConfigJSON: currentProviderConfigJSON())
            return decoded
        }
        if let rawOption = options?[VdpiSettings.providerConfigSettingsKey],
           let decoded = Self.decodeSettings(from: rawOption)
        {
            persistIfWritable(decoded, appGroupWritable: appGroupWritable)
            cacheLoadedSettings(decoded, providerConfigJSON: currentProviderConfigJSON())
            return decoded
        }

        let protoJSON = currentProviderConfigJSON()

        // During live `.reloadEngine`, iOS may not immediately refresh `self.protocolConfiguration`
        // in-process after `saveToPreferences()`. When App Group is writable and `providerConfiguration`
        // has not changed since launch, prefer the freshly saved App Group settings.
        if preferAppGroupWhenProviderConfigUnchanged, appGroupWritable {
            stateLock.lock()
            let previousProtoJSON = lastProviderConfigJSON
            stateLock.unlock()
            if protoJSON == previousProtoJSON {
                let fromGroup = VdpiAppGroup.loadSettings()
                cacheLoadedSettings(fromGroup, providerConfigJSON: protoJSON)
                return fromGroup
            }
        }

        // Tier 2: `NETunnelProviderProtocol.providerConfiguration` payload.
        if let protoJSON, let decoded = Self.decodeSettings(from: protoJSON) {
            persistIfWritable(decoded, appGroupWritable: appGroupWritable)
            cacheLoadedSettings(decoded, providerConfigJSON: protoJSON)
            return decoded
        }
        if let proto = protocolConfiguration as? NETunnelProviderProtocol,
           let rawConfig = proto.providerConfiguration?[VdpiSettings.providerConfigSettingsKey],
           let decoded = Self.decodeSettings(from: rawConfig)
        {
            persistIfWritable(decoded, appGroupWritable: appGroupWritable)
            cacheLoadedSettings(decoded, providerConfigJSON: protoJSON)
            return decoded
        }

        // Tier 3: App Group UserDefaults fallback (or last known effective settings if App Group is unusable).
        if !appGroupWritable {
            stateLock.lock()
            let cached = lastEffectiveSettings
            stateLock.unlock()
            if let cached {
                return cached
            }
        }

        let fallback = VdpiAppGroup.loadSettings()
        cacheLoadedSettings(fallback, providerConfigJSON: protoJSON)
        return fallback
    }

    private func currentProviderConfigJSON() -> String? {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol else {
            return nil
        }
        return proto.providerConfiguration?[VdpiSettings.providerConfigSettingsKey] as? String
    }

    private func persistIfWritable(_ settings: VdpiSettings, appGroupWritable: Bool) {
        if appGroupWritable {
            VdpiAppGroup.saveSettings(settings)
        }
    }

    private func cacheLoadedSettings(_ settings: VdpiSettings, providerConfigJSON: String?) {
        stateLock.lock()
        lastEffectiveSettings = settings
        lastProviderConfigJSON = providerConfigJSON
        stateLock.unlock()
    }

    private static func decodeSettings(from raw: Any?) -> VdpiSettings? {
        if let json = raw as? String {
            let trimmed = json.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, let data = trimmed.data(using: .utf8) else {
                return nil
            }
            return try? JSONDecoder().decode(VdpiSettings.self, from: data)
        }
        if let data = raw as? Data, !data.isEmpty {
            return try? JSONDecoder().decode(VdpiSettings.self, from: data)
        }
        return nil
    }

    private static func isAppGroupContainerWritable() -> Bool {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: VdpiAppGroup.suiteName
        ) else {
            return false
        }
        return FileManager.default.isWritableFile(atPath: containerURL.path)
    }

    private static func adaptiveCacheDirectoryURL() -> URL? {
        if let groupURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: VdpiAppGroup.suiteName
        ) {
            return groupURL
        }
        return FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first
    }

    private static func adaptiveCacheFileURL() -> URL? {
        adaptiveCacheDirectoryURL()?.appendingPathComponent("adaptive-cache.json")
    }

    private static func buildEngineConfigJSON(
        from settings: VdpiSettings,
        effectiveIpv4Only: Bool,
        effectiveMtu: Int
    ) -> String {
        var effectiveSettings = settings
        effectiveSettings.ipv4Only = effectiveIpv4Only
        effectiveSettings.mtu = effectiveMtu
        var tunnelConfig = effectiveSettings.toNativeConfig(cachePath: adaptiveCacheFileURL()?.path)
        tunnelConfig.mtu = effectiveMtu
        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(tunnelConfig),
              let json = String(data: data, encoding: .utf8)
        else {
            return "{}"
        }
        return json
    }

    private static func removeAdaptiveCacheFile() {
        var directories: [URL] = []
        if let groupURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: VdpiAppGroup.suiteName
        ) {
            directories.append(groupURL)
        }
        if let cachesURL = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first {
            directories.append(cachesURL)
        }
        for directory in directories {
            for filename in ["adaptive-cache.json", "adaptive-cache.tmp", "adaptive-cache.json.tmp"] {
                let fileURL = directory.appendingPathComponent(filename)
                if FileManager.default.fileExists(atPath: fileURL.path) {
                    try? FileManager.default.removeItem(at: fileURL)
                }
            }
        }
    }
}
