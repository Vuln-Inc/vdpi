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
        // iOS mDNSResponder resolves both A and AAAA cleanly over the virtual IPv4 DNS server,
        // avoiding any IPv6 DNS routing/exclusion mismatch.
        XCTAssertEqual(
            dualStack.dnsSettings?.servers,
            [TunnelNetworkSettingsBuilder.tunnelDnsServer]
        )
        XCTAssertFalse(TunnelNetworkSettingsBuilder.tunnelIpv6Address.lowercased().hasPrefix("fd"))
        XCTAssertFalse(TunnelNetworkSettingsBuilder.tunnelIpv6Address.lowercased().hasPrefix("fc"))
        XCTAssertNotNil(dualStack.ipv4Settings)
        XCTAssertNotNil(dualStack.ipv6Settings)
        XCTAssertGreaterThanOrEqual(dualStack.ipv4Settings?.excludedRoutes?.count ?? 0, 10)

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

    func testFormatStageLabelMapsKnownStrategiesAndPreservesFallback() {
        XCTAssertEqual(VdpiFormatters.formatStageLabel("ComboMultiRecord"), "Combo")
        XCTAssertEqual(VdpiFormatters.formatStageLabel("OobSniDesync"), "OOB SNI")
        XCTAssertEqual(VdpiFormatters.formatStageLabel("MultiRecordOob"), "Multi + OOB")
        XCTAssertEqual(VdpiFormatters.formatStageLabel("FineFragment"), "Fine Fragment")
        XCTAssertEqual(VdpiFormatters.formatStageLabel("DeepRecordStorm"), "Deep Storm")
        XCTAssertEqual(VdpiFormatters.formatStageLabel("SlowSniSlice"), "Slow SNI")
        XCTAssertEqual(VdpiFormatters.formatStageLabel("DirectPassthrough"), "Passthrough")
        XCTAssertEqual(VdpiFormatters.formatStageLabel("CustomStage"), "CustomStage")
        XCTAssertEqual(VdpiFormatters.formatStageLabel(""), "")
    }

    func testVdpiPaletteUsesAppleSystemAccentsWithoutNeonGlow() {
        XCTAssertTrue(VdpiPalette.dark.isDark)
        XCTAssertFalse(VdpiPalette.light.isDark)
        XCTAssertNotEqual(VdpiPalette.dark, VdpiPalette.light)

        XCTAssertEqual(VdpiPalette.dark.accent, Color(hex: 0x409CFF))
        XCTAssertEqual(VdpiPalette.dark.accentTint, Color(hex: 0x409CFF, alpha: 0.16))
        XCTAssertEqual(VdpiPalette.dark.primaryButtonBg, Color(hex: 0x0066CC))
        XCTAssertEqual(VdpiPalette.dark.primaryButtonInk, Color(hex: 0xFFFFFF))
        XCTAssertEqual(VdpiPalette.dark.signal, Color(hex: 0x30D158))
        XCTAssertEqual(VdpiPalette.dark.signalGlow, .clear)
        XCTAssertEqual(VdpiPalette.dark.warningGlow, .clear)
        XCTAssertEqual(VdpiPalette.dark.dangerGlow, .clear)

        XCTAssertEqual(VdpiPalette.light.accent, Color(hex: 0x0066CC))
        XCTAssertEqual(VdpiPalette.light.accentTint, Color(hex: 0x0066CC, alpha: 0.12))
        XCTAssertEqual(VdpiPalette.light.primaryButtonBg, Color(hex: 0x0066CC))
        XCTAssertEqual(VdpiPalette.light.primaryButtonInk, Color(hex: 0xFFFFFF))
        XCTAssertEqual(VdpiPalette.light.signal, Color(hex: 0x1E7E34))
        XCTAssertEqual(VdpiPalette.light.signalGlow, .clear)
        XCTAssertEqual(VdpiPalette.light.warningGlow, .clear)
        XCTAssertEqual(VdpiPalette.light.dangerGlow, .clear)
    }

    func testSettingsDefaultThemeAndDecodeFallbackIsSystem() throws {
        XCTAssertEqual(VdpiSettings().theme, .system)

        let emptyJson = try XCTUnwrap("{}".data(using: .utf8))
        let decoded = try JSONDecoder().decode(VdpiSettings.self, from: emptyJson)
        XCTAssertEqual(decoded.theme, .system)
    }

    func testDesyncModeSubtitlesMatchAndroidParity() {
        XCTAssertEqual(
            DesyncMode.combo.subtitle,
            "4-record TLS split + adaptive 7-stage auto-heal"
        )
        XCTAssertEqual(
            DesyncMode.tlsRecord.subtitle,
            "Split ClientHello across two RFC TLS records"
        )
        XCTAssertEqual(
            DesyncMode.fragment.subtitle,
            "Single outer TLS record sliced at SNI boundaries"
        )
        XCTAssertEqual(
            DesyncMode.split.subtitle,
            "Initial chunk-byte TCP split on first flight"
        )
    }

    func testUpdateCheckerSemverComparison() {
        XCTAssertTrue(VdpiUpdateChecker.isNewerVersion("v0.4.1", than: "0.4.0"))
        XCTAssertTrue(VdpiUpdateChecker.isNewerVersion("0.10.0", than: "0.9.9"))
        XCTAssertFalse(VdpiUpdateChecker.isNewerVersion("0.4.0", than: "v0.4.0"))
        XCTAssertFalse(VdpiUpdateChecker.isNewerVersion("0.3.9", than: "0.4.0"))
        XCTAssertFalse(VdpiUpdateChecker.isNewerVersion("0.4.1-beta.1", than: "0.4.0"))
    }

    func testNativeEngineConfigCachePathJsonRoundTripAndLegacyDecode() throws {
        var config = NativeEngineConfig(
            mode: .combo,
            chunkSize: 10,
            dnsAddr: "1.1.1.1",
            enableDoh: true,
            ipv4Only: false,
            blockQuic: true,
            mtu: 1400,
            bypassDomains: ["example.com"]
        )
        config.cachePath = "/tmp/vdpi/strategy_cache.json"

        let encoded = try JSONEncoder().encode(config)
        let dict = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        XCTAssertEqual(dict["cache_path"] as? String, "/tmp/vdpi/strategy_cache.json")

        let decoded = try JSONDecoder().decode(NativeEngineConfig.self, from: encoded)
        XCTAssertEqual(decoded, config)
        XCTAssertEqual(decoded.cachePath, "/tmp/vdpi/strategy_cache.json")

        let legacyJson = """
        {
            "mode": "combo",
            "chunk_size": 10,
            "dns_addr": "1.1.1.1",
            "enable_doh": true,
            "ipv4_only": false,
            "block_quic": true,
            "timeout_ms": 8000,
            "mtu": 1400,
            "bypass_domains": ["example.com"]
        }
        """
        let legacyData = try XCTUnwrap(legacyJson.data(using: .utf8))
        let legacyDecoded = try JSONDecoder().decode(NativeEngineConfig.self, from: legacyData)
        XCTAssertNil(legacyDecoded.cachePath)
        XCTAssertEqual(legacyDecoded.mode, .combo)
        XCTAssertEqual(legacyDecoded.mtu, 1400)
        XCTAssertEqual(legacyDecoded.bypassDomains, ["example.com"])
    }

    func testProvisioningProfileAppGroupExtraction() throws {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Entitlements</key>
            <dict>
                <key>com.apple.security.application-groups</key>
                <array>
                    <string>group.com.custom.vdpi.TEAM123</string>
                </array>
            </dict>
        </dict>
        </plist>
        """
        var cmsWrapped = Data([0x30, 0x82, 0x01, 0x00, 0x06, 0x09])
        cmsWrapped.append(Data(xml.utf8))
        cmsWrapped.append(Data([0x00, 0xFF, 0xA1, 0xB2]))

        XCTAssertEqual(
            VdpiAppGroup.extractAppGroupFromProvisioningProfile(cmsWrapped),
            "group.com.custom.vdpi.TEAM123"
        )
        XCTAssertNil(VdpiAppGroup.extractAppGroupFromProvisioningProfile(Data("not a plist".utf8)))
        XCTAssertNil(VdpiAppGroup.extractAppGroupFromProvisioningProfile(Data()))
    }
}
