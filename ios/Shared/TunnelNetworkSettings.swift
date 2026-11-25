import Darwin
import Foundation
import NetworkExtension

/// Builds `NEPacketTunnelNetworkSettings` for the local userspace TUN engine.
///
/// Uses RFC 2544 (`198.18.0.0/24`) for the virtual IPv4 tunnel interface and dummy DNS
/// (`198.18.0.1`, intercepted on port 53 by `vdpi-tun`), allowing all RFC 1918 LAN ranges
/// (`10/8`, `172.16/12`, `192.168/16`) and RFC 6598 CGNAT (`100.64/10`) to be cleanly excluded
/// without subnet overlap. IPv6 uses RFC 5180 benchmarking space (`2001:2:0:198::/120`) so
/// it stays completely outside the `fc00::/7` ULA exclusion route.
public enum TunnelNetworkSettingsBuilder {
    /// Maximum iOS utun MTU (`4064` matches WireGuardKit's iOS utun ceiling while keeping
    /// packet buffers comfortably within the 50 MB NetworkExtension Jetsam budget).
    public static let maxTunnelMtu: Int = 4064

    /// Distinct RFC 2544 remote endpoint OUTSIDE `198.18.0.0/24` so iOS does not install
    /// a host bypass route shadowing the virtual tunnel DNS server (`198.18.0.1`).
    public static let tunnelRemoteAddress = "198.19.0.1"
    public static let tunnelIpv4Address = "198.18.0.2"
    public static let tunnelIpv4Mask = "255.255.255.0"
    public static let tunnelDnsServer = "198.18.0.1"
    /// RFC 5180 IPv6 benchmarking prefix (`2001:2::/48`), strictly outside `fc00::/7`.
    public static let tunnelIpv6Address = "2001:2:0:198::2"
    public static let tunnelIpv6DnsServer = "2001:2:0:198::1"
    public static let tunnelIpv6PrefixLength: NSNumber = 120

    private static let ignoredInterfacePrefixes: [String] = [
        "utun", "lo", "awdl", "llw", "ipsec", "anpi", "ap", "bridge",
    ]

    public static func effectiveMtu(for settings: VdpiSettings) -> Int {
        min(max(settings.clampedMtu, 1280), maxTunnelMtu)
    }

    private static func isGlobalUnicastIpv6(_ addr: UnsafePointer<sockaddr>) -> Bool {
        guard addr.pointee.sa_family == UInt8(AF_INET6) else { return false }
        let sin6 = addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
        let firstByte = withUnsafeBytes(of: sin6.sin6_addr) { $0[0] }
        return (firstByte & 0xE0) == 0x20
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

    /// Returns `true` if `targetName` is `IFF_UP | IFF_RUNNING` (and non-loopback) and currently
    /// holds an RFC 4291 Global Unicast IPv6 address (`2000::/3`).
    ///
    /// When `targetName` is `nil` or empty, falls back to `hasGlobalIpv6OnPhysicalInterface()`.
    public static func hasGlobalIpv6(onInterface targetName: String?) -> Bool {
        guard let targetName, !targetName.isEmpty else {
            return hasGlobalIpv6OnPhysicalInterface()
        }

        var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrPtr) == 0, let first = ifaddrPtr else {
            return false
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
            guard let namePtr = current.pointee.ifa_name else { continue }
            guard String(cString: namePtr) == targetName else { continue }
            guard let addr = current.pointee.ifa_addr else { continue }
            if isGlobalUnicastIpv6(addr) {
                return true
            }
        }
        return false
    }

    /// Returns `true` if the active physical interface currently holds an RFC 4291 Global
    /// Unicast IPv6 address (`2000::/3`). Prevents advertising an IPv6 TUN default route on
    /// IPv4-only Wi-Fi networks where standby cellular (`pdp_ip*`) or Wi-Fi Calling (`ipsec*`)
    /// holds IPv6 while the active `en*` interface is IPv4-only.
    public static func hasGlobalIpv6OnPhysicalInterface() -> Bool {
        var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrPtr) == 0, let first = ifaddrPtr else {
            return false
        }
        defer { freeifaddrs(first) }

        var hasActiveEnInterface = false
        var hasNonCellularGlobalIpv6 = false
        var hasCellularGlobalIpv6 = false

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            defer { cursor = current.pointee.ifa_next }
            let flags = Int32(bitPattern: current.pointee.ifa_flags)
            guard (flags & IFF_UP) != 0,
                  (flags & IFF_RUNNING) != 0,
                  (flags & IFF_LOOPBACK) == 0
            else { continue }
            guard let namePtr = current.pointee.ifa_name else { continue }
            let name = String(cString: namePtr)
            if ignoredInterfacePrefixes.contains(where: { name.hasPrefix($0) }) {
                continue
            }
            guard let addr = current.pointee.ifa_addr else { continue }

            let isEn = name.hasPrefix("en")
            if isEn && isRoutableIpv4(addr) {
                hasActiveEnInterface = true
                continue
            }
            if isGlobalUnicastIpv6(addr) {
                if name.hasPrefix("pdp_ip") {
                    hasCellularGlobalIpv6 = true
                } else {
                    if isEn {
                        hasActiveEnInterface = true
                    }
                    hasNonCellularGlobalIpv6 = true
                }
            }
        }

        if hasActiveEnInterface {
            return hasNonCellularGlobalIpv6
        }
        return hasNonCellularGlobalIpv6 || hasCellularGlobalIpv6
    }

    public static func build(
        settings: VdpiSettings,
        effectiveIpv4Only: Bool? = nil
    ) -> NEPacketTunnelNetworkSettings {
        let ipv4Only = effectiveIpv4Only ?? settings.ipv4Only
        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: tunnelRemoteAddress)
        networkSettings.mtu = NSNumber(value: effectiveMtu(for: settings))

        // IPv4: capture internet traffic while excluding loopback, link-local, CGNAT,
        // RFC 1918 LANs, multicast, reserved (240/4), and broadcast.
        let ipv4 = NEIPv4Settings(addresses: [tunnelIpv4Address], subnetMasks: [tunnelIpv4Mask])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        ipv4.excludedRoutes = [
            NEIPv4Route(destinationAddress: "0.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "100.64.0.0", subnetMask: "255.192.0.0"),
            NEIPv4Route(destinationAddress: "127.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "169.254.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "172.16.0.0", subnetMask: "255.240.0.0"),
            NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "224.0.0.0", subnetMask: "240.0.0.0"),
            NEIPv4Route(destinationAddress: "240.0.0.0", subnetMask: "240.0.0.0"),
            NEIPv4Route(destinationAddress: "255.255.255.255", subnetMask: "255.255.255.255"),
        ]
        networkSettings.ipv4Settings = ipv4

        // IPv6: enabled only when user allows IPv6 AND the active interface has global IPv6.
        if !ipv4Only {
            let ipv6 = NEIPv6Settings(
                addresses: [tunnelIpv6Address],
                networkPrefixLengths: [tunnelIpv6PrefixLength]
            )
            ipv6.includedRoutes = [NEIPv6Route.default()]
            ipv6.excludedRoutes = [
                NEIPv6Route(destinationAddress: "::1", networkPrefixLength: 128),
                NEIPv6Route(destinationAddress: "fc00::", networkPrefixLength: 7),
                NEIPv6Route(destinationAddress: "fe80::", networkPrefixLength: 10),
                NEIPv6Route(destinationAddress: "ff00::", networkPrefixLength: 8),
            ]
            networkSettings.ipv6Settings = ipv6
        }

        // Route all DNS queries through the IPv4 virtual tunnel DNS address (`198.18.0.1`).
        // iOS `mDNSResponder` resolves both A and AAAA records over `198.18.0.1` without
        // risking IPv6 DNS blackholing across dual-stack network transitions.
        let dns = NEDNSSettings(servers: [tunnelDnsServer])
        dns.matchDomains = [""]
        dns.matchDomainsNoSearch = true
        networkSettings.dnsSettings = dns

        return networkSettings
    }
}
