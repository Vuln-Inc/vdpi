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

    public static func build(settings: VdpiSettings) -> NEPacketTunnelNetworkSettings {
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

        // IPv6: enabled unless user explicitly selected IPv4-only mode.
        if !settings.ipv4Only {
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
