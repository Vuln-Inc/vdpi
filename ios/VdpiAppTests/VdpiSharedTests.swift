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
        XCTAssertEqual(dict["bypass_domains"] as? [String], ["example.com", "*.local.test"])
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
        XCTAssertEqual(VdpiFormatters.normalizeBypassDomain("*.bank.gov.tr"), "*.bank.gov.tr")
        XCTAssertNil(VdpiFormatters.normalizeBypassDomain("not-a-domain"))
        XCTAssertNil(VdpiFormatters.normalizeBypassDomain("   "))
    }

    func testTunnelNetworkSettingsExcludeLanAndHonorIpv4Only() {
        let dualStack = TunnelNetworkSettingsBuilder.build(settings: VdpiSettings(ipv4Only: false, mtu: 1450))
        XCTAssertEqual(dualStack.mtu, 1450)
        XCTAssertEqual(dualStack.dnsSettings?.servers, [TunnelNetworkSettingsBuilder.tunnelDnsServer])
        XCTAssertNotNil(dualStack.ipv4Settings)
        XCTAssertNotNil(dualStack.ipv6Settings)
        XCTAssertGreaterThanOrEqual(dualStack.ipv4Settings?.excludedRoutes?.count ?? 0, 6)

        let v4Only = TunnelNetworkSettingsBuilder.build(settings: VdpiSettings(ipv4Only: true))
        XCTAssertNotNil(v4Only.ipv4Settings)
        XCTAssertNil(v4Only.ipv6Settings)
    }

    func testNativeRustBridgeLinksAndReturnsVersionAndIdleSnapshot() {
        let ver = VdpiNativeBridge.version()
        XCTAssertFalse(ver.isEmpty)

        let snap = VdpiNativeBridge.snapshot()
        XCTAssertFalse(snap.running)
    }
}
