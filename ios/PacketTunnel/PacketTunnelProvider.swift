import Foundation
import Network
import NetworkExtension

private let ipv4ProtocolNumber = NSNumber(value: AF_INET)
private let ipv6ProtocolNumber = NSNumber(value: AF_INET6)

private func vdpiOutboundPacketCallback(
    data: UnsafePointer<UInt8>?,
    len: Int,
    family: UInt8,
    userCtx: UnsafeMutableRawPointer?
) {
    // Runs on a long-lived Rust Tokio pthread with no RunLoop autorelease pool:
    // drain Objective-C bridged allocations immediately to stay well under 50 MB Jetsam.
    autoreleasepool {
        guard let data, len > 0, let userCtx else { return }
        let provider = Unmanaged<PacketTunnelProvider>.fromOpaque(userCtx).takeUnretainedValue()
        let packet = Data(bytes: data, count: len)
        let proto = (family == 6) ? ipv6ProtocolNumber : ipv4ProtocolNumber
        provider.writeOutboundPacket(packet, protocolNumber: proto)
    }
}

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let stateLock = NSLock()
    private var running = false
    private var stopping = false
    private var lastPathSignature: String?
    private var pathMonitor: NWPathMonitor?

    private let lifecycleQueue = DispatchQueue(label: "com.vulninc.vdpi.tunnel.lifecycle", qos: .userInitiated)
    private let doctorQueue = DispatchQueue(label: "com.vulninc.vdpi.tunnel.doctor", qos: .utility)
    private let monitorQueue = DispatchQueue(label: "com.vulninc.vdpi.tunnel.path", qos: .utility)

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

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        lifecycleQueue.async { [weak self] in
            guard let self else {
                completionHandler(nil)
                return
            }
            self.isStopping = false
            let settings = VdpiAppGroup.loadSettings()
            let effectiveIpv4Only = settings.ipv4Only || !TunnelNetworkSettingsBuilder.hasGlobalIpv6OnPhysicalInterface()
            let networkSettings = TunnelNetworkSettingsBuilder.build(
                settings: settings,
                effectiveIpv4Only: effectiveIpv4Only
            )

            self.setTunnelNetworkSettings(networkSettings) { [weak self] error in
                guard let self else {
                    completionHandler(error)
                    return
                }
                self.lifecycleQueue.async {
                    if self.isStopping {
                        completionHandler(NSError(
                            domain: "com.vulninc.vdpi.tunnel",
                            code: 1002,
                            userInfo: [NSLocalizedDescriptionKey: "Tunnel stopped during startup"]
                        ))
                        return
                    }
                    if let error {
                        completionHandler(error)
                        return
                    }

                    var effectiveSettings = settings
                    effectiveSettings.ipv4Only = effectiveIpv4Only
                    let configJson = effectiveSettings.toNativeConfigJSON()
                    let ctxPtr = Unmanaged.passUnretained(self).toOpaque()
                    if let errMsg = VdpiNativeBridge.start(
                        configJson: configJson,
                        writeCallback: vdpiOutboundPacketCallback,
                        userContext: ctxPtr
                    ) {
                        completionHandler(NSError(
                            domain: "com.vulninc.vdpi.tunnel",
                            code: 1001,
                            userInfo: [NSLocalizedDescriptionKey: errMsg]
                        ))
                        return
                    }

                    self.isRunning = true
                    self.startPathMonitoring()
                    self.pumpInboundPackets()
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
        // VdpiNativeBridge.stop() joins the Rust writer task and completionHandler returns.
        lifecycleQueue.async {
            VdpiNativeBridge.stop()
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
                completionHandler?(ProviderCommandResponse(ok: true).encodeData())
            }

        case .runDoctor(let configJson):
            // Run diagnostics on a dedicated queue so multi-second TLS probes never block reload/stop.
            doctorQueue.async {
                let reportJson = VdpiNativeBridge.runDoctorJson(configJson: configJson)
                completionHandler?(reportJson.data(using: .utf8))
            }

        case .reloadEngine:
            lifecycleQueue.async { [weak self] in
                guard let self, self.isRunning else {
                    completionHandler?(ProviderCommandResponse(ok: false, error: "Tunnel is not running").encodeData())
                    return
                }
                let settings = VdpiAppGroup.loadSettings()
                let effectiveIpv4Only = settings.ipv4Only || !TunnelNetworkSettingsBuilder.hasGlobalIpv6OnPhysicalInterface()
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
                        self.reasserting = false
                        guard self.isRunning else {
                            completionHandler?(ProviderCommandResponse(ok: false, error: "Tunnel stopped during reload").encodeData())
                            return
                        }
                        if let error {
                            completionHandler?(ProviderCommandResponse(ok: false, error: error.localizedDescription).encodeData())
                            return
                        }
                        var effectiveSettings = settings
                        effectiveSettings.ipv4Only = effectiveIpv4Only
                        let ctxPtr = Unmanaged.passUnretained(self).toOpaque()
                        if let errMsg = VdpiNativeBridge.start(
                            configJson: effectiveSettings.toNativeConfigJSON(),
                            writeCallback: vdpiOutboundPacketCallback,
                            userContext: ctxPtr
                        ) {
                            completionHandler?(ProviderCommandResponse(ok: false, error: errMsg).encodeData())
                        } else {
                            completionHandler?(ProviderCommandResponse(ok: true).encodeData())
                        }
                    }
                }
            }
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func wake() {
        lifecycleQueue.async { [weak self] in
            guard let self, self.isRunning else { return }
            VdpiNativeBridge.clearCache()
        }
    }

    fileprivate func writeOutboundPacket(_ packet: Data, protocolNumber: NSNumber) {
        guard isRunning else { return }
        packetFlow.writePackets([packet], withProtocols: [protocolNumber])
    }

    private func pumpInboundPackets() {
        guard isRunning else { return }
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, self.isRunning else { return }
            for packet in packets {
                VdpiNativeBridge.pushPacket(packet)
            }
            self.pumpInboundPackets()
        }
    }

    private func startPathMonitoring() {
        stopPathMonitoring()
        let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other])
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self, self.isRunning, path.status == .satisfied else { return }
            let signature = path.availableInterfaces
                .map { "\($0.name):\($0.type)" }
                .sorted()
                .joined(separator: ",")

            self.stateLock.lock()
            let previous = self.lastPathSignature
            self.lastPathSignature = signature
            self.stateLock.unlock()

            if let previous, previous != signature {
                self.lifecycleQueue.async { [weak self] in
                    guard let self, self.isRunning else { return }
                    VdpiNativeBridge.clearCache()
                }
            }
        }
        stateLock.lock()
        pathMonitor = monitor
        stateLock.unlock()
        monitor.start(queue: monitorQueue)
    }

    private func stopPathMonitoring() {
        stateLock.lock()
        let monitor = pathMonitor
        pathMonitor = nil
        lastPathSignature = nil
        stateLock.unlock()
        monitor?.cancel()
    }
}
