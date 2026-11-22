import Darwin
import Foundation
import NetworkExtension

/// Builds `NEPacketTunnelNetworkSettings` for the local userspace TUN engine.
///
/// Uses RFC 2544 (`198.18.0.0/24`) for the virtual tunnel interface and dummy DNS
/// (`198.18.0.1`, intercepted on port 53 by `vdpi-tun`), allowing all RFC 1918 LAN ranges
/// (`10/8`, `172.16/12`, `192.168/16`) to be cleanly excluded without subnet overlap.
public enum TunnelNetworkSettingsBuilder {
    public static let tunnelRemoteAddress = "198.18.0.1"
    public static let tunnelIpv4Address = "198.18.0.2"
    public static let tunnelIpv4Mask = "255.255.255.0"
    public static let tunnelDnsServer = "198.18.0.1"
    public static let tunnelIpv6Address = "fd00:198:18::2"
    public static let tunnelIpv6PrefixLength: NSNumber = 120

    /// Returns `true` if any active non-loopback, non-utun physical interface currently holds
    /// an RFC 4291 Global Unicast IPv6 address (`2000::/3`). Prevents advertising an IPv6 TUN
    /// default route on IPv4-only Wi-Fi/cellular networks where `smoltcp` would accept IPv6 SYNs
    /// locally before upstream dials fail with `ENETUNREACH`.
    public static func hasGlobalIpv6OnPhysicalInterface() -> Bool {
        var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrPtr) == 0, let first = ifaddrPtr else {
            return false
        }
        defer { freeifaddrs(first) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            defer { cursor = current.pointee.ifa_next }
            let flags = Int32(current.pointee.ifa_flags)
            guard (flags & IFF_UP) != 0, (flags & IFF_LOOPBACK) == 0 else { continue }
            guard let namePtr = current.pointee.ifa_name else { continue }
            let name = String(cString: namePtr)
            if name.hasPrefix("utun") || name.hasPrefix("lo") || name.hasPrefix("awdl") || name.hasPrefix("llw") {
                continue
            }
            guard let addr = current.pointee.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET6) else {
                continue
            }
            let sin6 = addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
            let firstByte = withUnsafeBytes(of: sin6.sin6_addr) { $0[0] }
            if (firstByte & 0xE0) == 0x20 {
                return true
            }
        }
        return false
    }

    public static func build(
        settings: VdpiSettings,
        effectiveIpv4Only: Bool? = nil
    ) -> NEPacketTunnelNetworkSettings {
        let ipv4Only = effectiveIpv4Only ?? settings.ipv4Only
        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: tunnelRemoteAddress)
        networkSettings.mtu = NSNumber(value: settings.clampedMtu)

        // IPv4: capture internet traffic while excluding loopback, link-local, multicast, and RFC 1918 LANs.
        let ipv4 = NEIPv4Settings(addresses: [tunnelIpv4Address], subnetMasks: [tunnelIpv4Mask])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        ipv4.excludedRoutes = [
            NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "127.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "169.254.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "172.16.0.0", subnetMask: "255.240.0.0"),
            NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "224.0.0.0", subnetMask: "240.0.0.0"),
        ]
        networkSettings.ipv4Settings = ipv4

        // IPv6: enabled only when user allows IPv6 AND physical connectivity actually has global IPv6.
        if !ipv4Only {
            let ipv6 = NEIPv6Settings(
                addresses: [tunnelIpv6Address],
                networkPrefixLengths: [tunnelIpv6PrefixLength]
            )
            ipv6.includedRoutes = [NEIPv6Route.default()]
            ipv6.excludedRoutes = [
                NEIPv6Route(destinationAddress: "::1", networkPrefixLength: 128),
                NEIPv6Route(destinationAddress: "fe80::", networkPrefixLength: 10),
                NEIPv6Route(destinationAddress: "ff00::", networkPrefixLength: 8),
            ]
            networkSettings.ipv6Settings = ipv6
        }

        // Route all DNS queries through the virtual tunnel DNS address so `vdpi-tun`
        // intercepts port 53 (UDP + TCP) and resolves via the anti-poisoning DoH ring.
        let dns = NEDNSSettings(servers: [tunnelDnsServer])
        dns.matchDomains = [""]
        dns.matchDomainsNoSearch = true
        networkSettings.dnsSettings = dns

        return networkSettings
    }
}
