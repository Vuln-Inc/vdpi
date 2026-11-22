import SwiftUI
import XCTest
@testable import VdpiApp

final class VdpiSharedTests: XCTestCase {
    func testNativeConfigWireJsonMatchesRustSchema() throws {
        let settings = VdpiSettings(
            desyncMode: .tlsRecord,
            chunkSize: 8,
            dnsAddr: "9.9.9.9",
            enableDoh: true,
            ipv4Only: true,
            blockQuic: false,
            mtu: 1420,
            bypassDomains: ["example.com", "*.local.test"]
        )

        let json = settings.toNativeConfigJSON()
        let data = try XCTUnwrap(json.data(using: .utf8))
        let dict = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(dict["mode"] as? String, "tls-record")
        XCTAssertEqual(dict["chunk_size"] as? Int, 8)
        XCTAssertEqual(dict["dns_addr"] as? String, "9.9.9.9")
        XCTAssertEqual(dict["enable_doh"] as? Bool, true)
        XCTAssertEqual(dict["ipv4_only"] as? Bool, true)
        XCTAssertEqual(dict["block_quic"] as? Bool, false)
        XCTAssertEqual(dict["mtu"] as? Int, 1420)
        XCTAssertEqual(dict["bypass_domains"] as? [String], ["*.local.test", "example.com"])
    }

    func testSettingsClampBoundsAndDetectTunnelReload() {
        let raw = VdpiSettings(chunkSize: 999, dnsAddr: "  ", mtu: 500)
        let native = raw.toNativeConfig()
        XCTAssertEqual(native.chunkSize, 64)
        XCTAssertEqual(native.dnsAddr, "1.1.1.1")
        XCTAssertEqual(native.mtu, 1280)

        var themeOnly = raw
        themeOnly.theme = .light
        XCTAssertFalse(themeOnly.requiresTunnelReload(comparedTo: raw))

        var dnsChanged = raw
        dnsChanged.dnsAddr = "8.8.8.8"
        XCTAssertTrue(dnsChanged.requiresTunnelReload(comparedTo: raw))
    }

    func testProviderMessageCodecRoundTrips() {
        let messages: [ProviderMessage] = [
            .snapshot,
            .clearCache,
            .reloadEngine,
            .runDoctor(configJson: "{\"mode\":\"combo\"}"),
        ]

        for msg in messages {
            let encoded = msg.encodeData()
            XCTAssertNotNil(encoded)
            XCTAssertEqual(encoded.flatMap(ProviderMessage.decodeData), msg)
        }
    }

    func testFormattersAndDomainValidation() {
        XCTAssertEqual(VdpiFormatters.formatBytes(512), "512 B")
        XCTAssertEqual(VdpiFormatters.formatBytes(2048), "2.0 KB")
        XCTAssertEqual(VdpiFormatters.formatBytes(1_048_576), "1.0 MB")
        XCTAssertEqual(VdpiFormatters.formatUptime(65), "01:05")
        XCTAssertEqual(VdpiFormatters.formatUptime(3661), "01:01:01")
        XCTAssertEqual(VdpiFormatters.formatStageShort(stageNumber: 5, label: "DeepRecordStorm"), "S5 · DeepRecordStorm")

        XCTAssertEqual(VdpiFormatters.normalizeBypassDomain("  HTTPS://Discord.COM/app "), "discord.com")
        XCTAssertEqual(VdpiFormatters.normalizeBypassDomain("*.MyBank.com:443."), "*.mybank.com")
        XCTAssertEqual(VdpiFormatters.normalizeBypassDomain("*.bank.gov.tr"), "*.bank.gov.tr")
        XCTAssertNil(VdpiFormatters.normalizeBypassDomain("not-a-domain"))
        XCTAssertNil(VdpiFormatters.normalizeBypassDomain("   "))

        XCTAssertTrue(VdpiFormatters.isValidDnsInput("1.1.1.1"))
        XCTAssertTrue(VdpiFormatters.isValidDnsInput("2606:4700:4700::1111"))
        XCTAssertTrue(VdpiFormatters.isValidDnsInput("https://dns.google/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("not-a-dns"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("http://insecure.example/dns-query"))
    }

    func testTunnelNetworkSettingsExcludeLanAndHonorIpv4Only() {
        XCTAssertNotEqual(
            TunnelNetworkSettingsBuilder.tunnelRemoteAddress,
            TunnelNetworkSettingsBuilder.tunnelDnsServer
        )

        let dualStack = TunnelNetworkSettingsBuilder.build(
            settings: VdpiSettings(ipv4Only: false, mtu: 1450),
            effectiveIpv4Only: false
        )
        XCTAssertEqual(dualStack.mtu, 1450)
        XCTAssertEqual(
            dualStack.dnsSettings?.servers,
            [TunnelNetworkSettingsBuilder.tunnelDnsServer, TunnelNetworkSettingsBuilder.tunnelIpv6DnsServer]
        )
        XCTAssertNotNil(dualStack.ipv4Settings)
        XCTAssertNotNil(dualStack.ipv6Settings)
        XCTAssertGreaterThanOrEqual(dualStack.ipv4Settings?.excludedRoutes?.count ?? 0, 8)

        let v4Only = TunnelNetworkSettingsBuilder.build(
            settings: VdpiSettings(ipv4Only: true),
            effectiveIpv4Only: true
        )
        XCTAssertNotNil(v4Only.ipv4Settings)
        XCTAssertNil(v4Only.ipv6Settings)
        XCTAssertEqual(v4Only.dnsSettings?.servers, [TunnelNetworkSettingsBuilder.tunnelDnsServer])
    }

    func testPartialFallbackTelemetryJsonAndCommandResponseDecode() throws {
        let minimal = try XCTUnwrap("{\"running\":false}".data(using: .utf8))
        let decoded = try JSONDecoder().decode(TelemetrySnapshot.self, from: minimal)
        XCTAssertFalse(decoded.running)
        XCTAssertEqual(decoded.dnsAddr, "1.1.1.1")

        let reply = ProviderCommandResponse(ok: false, error: "quoted \"error\"\nline2")
        let encoded = try XCTUnwrap(reply.encodeData())
        XCTAssertEqual(ProviderCommandResponse.decodeData(encoded), reply)
    }

    func testNativeRustBridgeLinksAndReturnsVersionAndIdleSnapshot() {
        let ver = VdpiNativeBridge.version()
        XCTAssertFalse(ver.isEmpty)

        let snap = VdpiNativeBridge.snapshot()
        XCTAssertFalse(snap.running)
    }

    func testChangedFieldLabelsAndOrderInvariantBypass() {
        let baseline = VdpiSettings(
            desyncMode: .combo,
            chunkSize: 10,
            dnsAddr: "1.1.1.1",
            enableDoh: true,
            ipv4Only: false,
            blockQuic: true,
            mtu: 1400,
            bypassDomains: ["a.com", "b.com"],
            onDemandEnabled: false,
            theme: .dark
        )

        var uiOnly = baseline
        uiOnly.theme = .light
        uiOnly.onDemandEnabled = true
        XCTAssertTrue(uiOnly.changedFieldLabels(comparedTo: baseline).isEmpty)
        XCTAssertFalse(uiOnly.requiresTunnelReload(comparedTo: baseline))

        var reorderedBypass = baseline
        reorderedBypass.bypassDomains = ["b.com", "a.com"]
        XCTAssertFalse(reorderedBypass.requiresTunnelReload(comparedTo: baseline))
        XCTAssertTrue(reorderedBypass.changedFieldLabels(comparedTo: baseline).isEmpty)

        var modeChanged = baseline
        modeChanged.desyncMode = .tlsRecord
        XCTAssertEqual(modeChanged.changedFieldLabels(comparedTo: baseline), ["Mode"])
        XCTAssertTrue(modeChanged.requiresTunnelReload(comparedTo: baseline))

        var chunkChanged = baseline
        chunkChanged.chunkSize = 16
        XCTAssertEqual(chunkChanged.changedFieldLabels(comparedTo: baseline), ["Chunk"])

        var dnsChanged = baseline
        dnsChanged.dnsAddr = "9.9.9.9"
        XCTAssertEqual(dnsChanged.changedFieldLabels(comparedTo: baseline), ["DNS"])

        var dohChanged = baseline
        dohChanged.enableDoh = false
        XCTAssertEqual(dohChanged.changedFieldLabels(comparedTo: baseline), ["DoH"])

        var ipv4Changed = baseline
        ipv4Changed.ipv4Only = true
        XCTAssertEqual(ipv4Changed.changedFieldLabels(comparedTo: baseline), ["IPv4"])

        var quicChanged = baseline
        quicChanged.blockQuic = false
        XCTAssertEqual(quicChanged.changedFieldLabels(comparedTo: baseline), ["QUIC"])

        var mtuChanged = baseline
        mtuChanged.mtu = 1440
        XCTAssertEqual(mtuChanged.changedFieldLabels(comparedTo: baseline), ["MTU"])

        var bypassChanged = baseline
        bypassChanged.bypassDomains = ["a.com", "b.com", "c.com"]
        XCTAssertEqual(bypassChanged.changedFieldLabels(comparedTo: baseline), ["Bypass"])

        let allChanged = VdpiSettings(
            desyncMode: .fragment,
            chunkSize: 20,
            dnsAddr: "8.8.8.8",
            enableDoh: false,
            ipv4Only: true,
            blockQuic: false,
            mtu: 1450,
            bypassDomains: ["c.com"],
            onDemandEnabled: true,
            theme: .light
        )
        let allLabels = allChanged.changedFieldLabels(comparedTo: baseline)
        XCTAssertEqual(allLabels.count, 8)
        XCTAssertEqual(
            Set(allLabels),
            Set(["Mode", "Chunk", "DNS", "DoH", "IPv4", "QUIC", "MTU", "Bypass"])
        )

        var reverted = allChanged
        reverted.desyncMode = baseline.desyncMode
        reverted.chunkSize = baseline.chunkSize
        reverted.dnsAddr = baseline.dnsAddr
        reverted.enableDoh = baseline.enableDoh
        reverted.ipv4Only = baseline.ipv4Only
        reverted.blockQuic = baseline.blockQuic
        reverted.mtu = baseline.mtu
        reverted.bypassDomains = ["b.com", "a.com"]
        XCTAssertEqual(reverted.changedFieldLabels(comparedTo: baseline), [])
        XCTAssertFalse(reverted.requiresTunnelReload(comparedTo: baseline))
    }

    func testAppliedConfigRoundTripInIsolatedUserDefaults() {
        let suiteName = "test.vdpi.applied.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer {
            defaults.removePersistentDomain(forName: suiteName)
        }

        XCTAssertNil(VdpiAppGroup.loadAppliedConfig(from: defaults))

        let cfg = NativeEngineConfig(
            mode: .tlsRecord,
            chunkSize: 12,
            dnsAddr: "9.9.9.9",
            enableDoh: false,
            ipv4Only: true,
            blockQuic: false,
            mtu: 1420,
            bypassDomains: ["a.com", "b.com"]
        )
        VdpiAppGroup.saveAppliedConfig(cfg, to: defaults)
        XCTAssertEqual(VdpiAppGroup.loadAppliedConfig(from: defaults), cfg)

        VdpiAppGroup.saveAppliedConfig(nil, to: defaults)
        XCTAssertNil(VdpiAppGroup.loadAppliedConfig(from: defaults))
    }

    func testVdpiPaletteDarkAndLightResolve() {
        XCTAssertTrue(VdpiPalette.resolve(preference: .dark, systemScheme: .light).isDark)
        XCTAssertTrue(VdpiPalette.resolve(preference: .dark, systemScheme: .dark).isDark)
        XCTAssertFalse(VdpiPalette.resolve(preference: .light, systemScheme: .dark).isDark)
        XCTAssertFalse(VdpiPalette.resolve(preference: .light, systemScheme: .light).isDark)
        XCTAssertTrue(VdpiPalette.resolve(preference: .system, systemScheme: .dark).isDark)
        XCTAssertFalse(VdpiPalette.resolve(preference: .system, systemScheme: .light).isDark)
    }
}
