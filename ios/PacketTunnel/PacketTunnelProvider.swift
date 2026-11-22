import Foundation
import Network
import NetworkExtension

private func vdpiOutboundPacketCallback(
    data: UnsafePointer<UInt8>?,
    len: Int,
    family: UInt8,
    userCtx: UnsafeMutableRawPointer?
) {
    guard let data, len > 0, let userCtx else { return }
    let provider = Unmanaged<PacketTunnelProvider>.fromOpaque(userCtx).takeUnretainedValue()
    let packet = Data(bytes: data, count: len)
    let proto: NSNumber = (family == 6) ? NSNumber(value: AF_INET6) : NSNumber(value: AF_INET)
    provider.writeOutboundPacket(packet, protocolNumber: proto)
}

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let stateLock = NSLock()
    private var running = false
    private var lastPathSignature: String?
    private var pathMonitor: NWPathMonitor?

    private let workQueue = DispatchQueue(label: "com.vulninc.vdpi.tunnel.work", qos: .userInitiated)
    private let monitorQueue = DispatchQueue(label: "com.vulninc.vdpi.tunnel.path", qos: .utility)

    private var isRunning: Bool {
        get {
            stateLock.lock()
            defer { stateLock.unlock() }
            return running
        }
        set {
            stateLock.lock()
            running = newValue
            stateLock.unlock()
        }
    }

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let settings = VdpiAppGroup.loadSettings()
        let effectiveIpv4Only = settings.ipv4Only || !TunnelNetworkSettingsBuilder.hasGlobalIpv6OnPhysicalInterface()
        let networkSettings = TunnelNetworkSettingsBuilder.build(
            settings: settings,
            effectiveIpv4Only: effectiveIpv4Only
        )

        setTunnelNetworkSettings(networkSettings) { [weak self] error in
            guard let self else {
                completionHandler(error)
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

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        isRunning = false
        stopPathMonitoring()
        // Guarantees the Rust writer task exits before `self` can be deallocated.
        VdpiNativeBridge.stop()
        completionHandler()
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
            workQueue.async {
                VdpiNativeBridge.clearCache()
                completionHandler?(Data("{\"ok\":true}".utf8))
            }

        case .runDoctor(let configJson):
            workQueue.async {
                let reportJson = VdpiNativeBridge.runDoctorJson(configJson: configJson)
                completionHandler?(reportJson.data(using: .utf8))
            }

        case .reloadEngine:
            workQueue.async { [weak self] in
                guard let self else {
                    completionHandler?(Data("{\"ok\":false}".utf8))
                    return
                }
                let settings = VdpiAppGroup.loadSettings()
                let effectiveIpv4Only = settings.ipv4Only || !TunnelNetworkSettingsBuilder.hasGlobalIpv6OnPhysicalInterface()
                let networkSettings = TunnelNetworkSettingsBuilder.build(
                    settings: settings,
                    effectiveIpv4Only: effectiveIpv4Only
                )
                self.setTunnelNetworkSettings(networkSettings) { [weak self] error in
                    guard let self else {
                        completionHandler?(Data("{\"ok\":false}".utf8))
                        return
                    }
                    if let error {
                        let msg = error.localizedDescription.replacingOccurrences(of: "\"", with: "'")
                        completionHandler?(Data("{\"ok\":false,\"error\":\"\(msg)\"}".utf8))
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
                        let clean = errMsg.replacingOccurrences(of: "\"", with: "'")
                        completionHandler?(Data("{\"ok\":false,\"error\":\"\(clean)\"}".utf8))
                    } else {
                        completionHandler?(Data("{\"ok\":true}".utf8))
                    }
                }
            }
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func wake() {
        workQueue.async {
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
        let monitor = NWPathMonitor()
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
                self.workQueue.async {
                    VdpiNativeBridge.clearCache()
                }
            }
        }
        monitor.start(queue: monitorQueue)
        pathMonitor = monitor
    }

    private func stopPathMonitoring() {
        pathMonitor?.cancel()
        pathMonitor = nil
        stateLock.lock()
        lastPathSignature = nil
        stateLock.unlock()
    }
}
