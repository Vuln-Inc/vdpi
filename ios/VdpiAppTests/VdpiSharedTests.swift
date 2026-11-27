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

    func testRedactedDnsSummaryHandlesIpv4Ipv6MalformedHttpsAndDetails() {
        XCTAssertEqual(TunnelManager.redactedDnsSummary("1.1.1.1"), "1.1.1.1")
        XCTAssertEqual(TunnelManager.redactedDnsSummary("   "), "1.1.1.1")
        XCTAssertEqual(
            TunnelManager.redactedDnsSummary("2606:4700:4700::1111"),
            "2606:4700:4700::1111"
        )
        XCTAssertEqual(
            TunnelManager.redactedDnsSummary("https://dns.google/dns-query"),
            "https://dns.google/dns-query"
        )
        XCTAssertEqual(
            TunnelManager.redactedDnsSummary("https://dns.nextdns.io/abc123/iphone"),
            "https://dns.nextdns.io/[redacted]"
        )
        XCTAssertEqual(
            TunnelManager.redactedDnsSummary("https://dns.example.com/dns-query?token=secret"),
            "https://dns.example.com/[redacted]"
        )
        XCTAssertEqual(
            TunnelManager.redactedDnsSummary("https://[2606:4700:4700::1111]/dns-query"),
            "https://[2606:4700:4700::1111]/dns-query"
        )
        XCTAssertEqual(
            TunnelManager.redactedDnsSummary("https://[2606:4700:4700::1111]:8443/profile-secret"),
            "https://[2606:4700:4700::1111]:8443/[redacted]"
        )
        XCTAssertEqual(
            TunnelManager.redactedDnsSummary("https://dns.nextdns.io/abc123 -> discord.com"),
            "https://dns.nextdns.io/[redacted] -> discord.com"
        )
        XCTAssertEqual(
            TunnelManager.redactedDnsSummary("https://[2606:4700:4700::1111]/secret -> discord.com"),
            "https://[2606:4700:4700::1111]/[redacted] -> discord.com"
        )

        // Malformed https:// inputs must never leak raw URL text.
        XCTAssertEqual(TunnelManager.redactedDnsSummary("https://"), "Custom DoH")
        XCTAssertEqual(TunnelManager.redactedDnsSummary("https:///secret-profile"), "Custom DoH")
        XCTAssertEqual(TunnelManager.redactedDnsSummary("https://[bad-ipv6/secret-token"), "Custom DoH")
        XCTAssertEqual(TunnelManager.redactedDnsSummary("https://dns.nextdns.io:badport/secret"), "Custom DoH")
        XCTAssertEqual(
            TunnelManager.redactedDnsSummary("HTTPS://[bad/secret -> discord.com"),
            "Custom DoH -> discord.com"
        )
        let withSpace = TunnelManager.redactedDnsSummary("https://dns.nextdns.io/secret with space")
        XCTAssertFalse(withSpace.contains("secret"))

        // Doctor detail strings must also redact embedded https:// URLs.
        XCTAssertEqual(
            TunnelManager.redactHttpsUrls(
                in: "error sending request for url (https://dns.nextdns.io/abc123/device?key=1): reset"
            ),
            "error sending request for url (https://dns.nextdns.io/[redacted]): reset"
        )
        XCTAssertEqual(
            TunnelManager.redactHttpsUrls(
                in: "failed connecting to https://[2606:4700:4700::1111]:8443/secret-id."
            ),
            "failed connecting to https://[2606:4700:4700::1111]:8443/[redacted]."
        )
        XCTAssertEqual(
            TunnelManager.redactHttpsUrls(
                in: "malformed url https://[bad/secret-token failed"
            ),
            "malformed url Custom DoH failed"
        )
        XCTAssertEqual(
            TunnelManager.redactHttpsUrls(in: "resolved 162.159.135.232 (2 records)"),
            "resolved 162.159.135.232 (2 records)"
        )
    }

    func testPushPacketsPartialAcceptanceBreaksBeforeNextChunk() {
        let cfg = "{\"enable_doh\":false,\"block_quic\":true,\"ipv4_only\":true,\"mtu\":4064}"
        let startError = VdpiNativeBridge.startBatched(
            configJSON: cfg,
            writeBatchCallback: { _, _, _ in },
            userCtx: nil
        )
        XCTAssertNil(startError)
        defer { VdpiNativeBridge.stop() }

        let validPacket = Data(repeating: 0, count: 20)
        let undersizedPacket = Data(repeating: 0, count: 10)

        // Chunk 1 (64 packets): 63 valid + 1 undersized -> native accepts 63 (< 64).
        // Chunk 2 (64 packets): 64 valid -> must NOT be pushed because chunk 1 partially accepted.
        var mixedBatch = Array(repeating: validPacket, count: 63)
        mixedBatch.append(undersizedPacket)
        mixedBatch.append(contentsOf: Array(repeating: validPacket, count: 64))
        XCTAssertEqual(mixedBatch.count, 128)

        let partialAccepted = VdpiNativeBridge.pushPackets(mixedBatch)
        XCTAssertEqual(partialAccepted, 63)

        // Full multi-chunk batch (64 + 6) continues across chunks when chunk 1 fully accepts.
        let validMultiChunk = Array(repeating: validPacket, count: 70)
        XCTAssertEqual(VdpiNativeBridge.pushPackets(validMultiChunk), 70)

        XCTAssertEqual(VdpiNativeBridge.pushPackets([]), 0)

        VdpiNativeBridge.stop()
        XCTAssertEqual(VdpiNativeBridge.pushPackets(validMultiChunk), 0)
    }

    func testJsonImportNormalizesEnableDohForHttpsDns() throws {
        let httpsWithDohDisabled = """
        {
            "dnsAddr": "https://dns.google/dns-query",
            "enableDoh": false
        }
        """
        let importedHttps = try TunnelManager.parseImportedSettings(httpsWithDohDisabled)
        XCTAssertEqual(importedHttps.dnsAddr, "https://dns.google/dns-query")
        XCTAssertTrue(importedHttps.enableDoh)

        let uppercaseHttps = """
        {
            "dnsAddr": "  HTTPS://dns.nextdns.io/abc123  ",
            "enableDoh": false
        }
        """
        let importedUpper = try TunnelManager.parseImportedSettings(uppercaseHttps)
        XCTAssertEqual(importedUpper.dnsAddr, "HTTPS://dns.nextdns.io/abc123")
        XCTAssertTrue(importedUpper.enableDoh)

        let ipv6Https = """
        {
            "dnsAddr": "https://[2606:4700:4700::1111]/dns-query",
            "enableDoh": false
        }
        """
        let importedIpv6Https = try TunnelManager.parseImportedSettings(ipv6Https)
        XCTAssertEqual(importedIpv6Https.dnsAddr, "https://[2606:4700:4700::1111]/dns-query")
        XCTAssertTrue(importedIpv6Https.enableDoh)

        let plainIpv4WithDohDisabled = """
        {
            "dnsAddr": "9.9.9.9",
            "enableDoh": false
        }
        """
        let importedIpv4 = try TunnelManager.parseImportedSettings(plainIpv4WithDohDisabled)
        XCTAssertEqual(importedIpv4.dnsAddr, "9.9.9.9")
        XCTAssertFalse(importedIpv4.enableDoh)

        let plainIpv6WithDohDisabled = """
        {
            "dnsAddr": "2606:4700:4700::1111",
            "enableDoh": false
        }
        """
        let importedIpv6 = try TunnelManager.parseImportedSettings(plainIpv6WithDohDisabled)
        XCTAssertEqual(importedIpv6.dnsAddr, "2606:4700:4700::1111")
        XCTAssertFalse(importedIpv6.enableDoh)
    }

    func testLegacyHttpsWithEnableDohFalseNormalizesOnVdpiSettingsAndNativeEngineConfig() throws {
        // Direct VdpiSettings Codable decode (legacy persisted JSON).
        let legacySettingsJson = """
        {
            "dnsAddr": "  HTTPS://dns.nextdns.io/abc123  ",
            "enableDoh": false
        }
        """
        let decodedSettings = try JSONDecoder().decode(
            VdpiSettings.self,
            from: try XCTUnwrap(legacySettingsJson.data(using: .utf8))
        )
        XCTAssertTrue(decodedSettings.enableDoh)

        let legacyPlainIpSettingsJson = """
        {
            "dnsAddr": "9.9.9.9",
            "enableDoh": false
        }
        """
        let decodedPlainSettings = try JSONDecoder().decode(
            VdpiSettings.self,
            from: try XCTUnwrap(legacyPlainIpSettingsJson.data(using: .utf8))
        )
        XCTAssertFalse(decodedPlainSettings.enableDoh)

        // Direct NativeEngineConfig init with https:// and enableDoh: false.
        let directHttpsConfig = NativeEngineConfig(
            dnsAddr: "https://dns.google/dns-query",
            enableDoh: false
        )
        XCTAssertTrue(directHttpsConfig.enableDoh)

        let directUpperHttpsConfig = NativeEngineConfig(
            dnsAddr: "  HTTPS://[2606:4700:4700::1111]/dns-query  ",
            enableDoh: false
        )
        XCTAssertEqual(directUpperHttpsConfig.dnsAddr, "HTTPS://[2606:4700:4700::1111]/dns-query")
        XCTAssertTrue(directUpperHttpsConfig.enableDoh)

        let directPlainIpConfig = NativeEngineConfig(
            dnsAddr: "9.9.9.9",
            enableDoh: false
        )
        XCTAssertFalse(directPlainIpConfig.enableDoh)

        // NativeEngineConfig Codable decode (legacy persisted applied config JSON).
        let legacyNativeJson = """
        {
            "mode": "combo",
            "chunk_size": 10,
            "dns_addr": "https://dns.nextdns.io/abc123",
            "enable_doh": false,
            "ipv4_only": false,
            "block_quic": true,
            "timeout_ms": 8000,
            "mtu": 4064,
            "bypass_domains": []
        }
        """
        let decodedNative = try JSONDecoder().decode(
            NativeEngineConfig.self,
            from: try XCTUnwrap(legacyNativeJson.data(using: .utf8))
        )
        XCTAssertEqual(decodedNative.dnsAddr, "https://dns.nextdns.io/abc123")
        XCTAssertTrue(decodedNative.enableDoh)

        let legacyNativePlainIpJson = """
        {
            "dns_addr": "8.8.8.8",
            "enable_doh": false
        }
        """
        let decodedNativePlainIp = try JSONDecoder().decode(
            NativeEngineConfig.self,
            from: try XCTUnwrap(legacyNativePlainIpJson.data(using: .utf8))
        )
        XCTAssertFalse(decodedNativePlainIp.enableDoh)
    }

    func testTelemetrySnapshotDecodesDroppedPacketsWithZeroDefault() throws {
        XCTAssertEqual(TelemetrySnapshot.idle.droppedPackets, 0)

        let missingDroppedJson = try XCTUnwrap("{\"running\":true,\"udp_flows_active\":3}".data(using: .utf8))
        let missingDecoded = try JSONDecoder().decode(TelemetrySnapshot.self, from: missingDroppedJson)
        XCTAssertTrue(missingDecoded.running)
        XCTAssertEqual(missingDecoded.udpFlowsActive, 3)
        XCTAssertEqual(missingDecoded.droppedPackets, 0)

        let withDroppedJson = try XCTUnwrap(
            "{\"running\":true,\"udp_flows_active\":2,\"dropped_packets\":42}".data(using: .utf8)
        )
        let withDroppedDecoded = try JSONDecoder().decode(TelemetrySnapshot.self, from: withDroppedJson)
        XCTAssertEqual(withDroppedDecoded.droppedPackets, 42)

        let reencoded = try JSONEncoder().encode(withDroppedDecoded)
        let dict = try XCTUnwrap(JSONSerialization.jsonObject(with: reencoded) as? [String: Any])
        XCTAssertEqual((dict["dropped_packets"] as? NSNumber)?.uint64Value, 42)
        let roundTripped = try JSONDecoder().decode(TelemetrySnapshot.self, from: reencoded)
        XCTAssertEqual(roundTripped.droppedPackets, 42)
    }

    func testTightenedIsValidDnsInputMatchesRustDohValidation() {
        // Valid HTTPS DoH endpoints
        XCTAssertTrue(VdpiFormatters.isValidDnsInput("https://dns.google/dns-query"))
        XCTAssertTrue(VdpiFormatters.isValidDnsInput("https://dns.quad9.net:443/dns-query"))
        XCTAssertTrue(VdpiFormatters.isValidDnsInput("https://1.1.1.1/dns-query"))
        XCTAssertTrue(VdpiFormatters.isValidDnsInput("https://[2606:4700:4700::1111]/dns-query"))
        XCTAssertTrue(VdpiFormatters.isValidDnsInput("https://[2606:4700:4700::1111]:8443/dns-query?token=abc%201"))
        XCTAssertTrue(VdpiFormatters.isValidDnsInput("HTTPS://dns.nextdns.io/abc123"))

        // Reject fragments
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://dns.google/dns-query#frag"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://dns.google/dns-query#"))

        // Reject userinfo credentials
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://user:pass@dns.google/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://user@dns.google/dns-query"))

        // Reject loopback, link-local, unspecified, multicast, broadcast, and single-label localhost
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://127.0.0.1/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://127.0.0.53/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://169.254.1.1/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://0.0.0.0/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://224.0.0.1/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://255.255.255.255/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://[::1]/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://[fe80::1]/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://[::]/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://[ff02::1]/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://[::ffff:127.0.0.1]/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://[::ffff:169.254.1.1]/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://localhost/dns-query"))

        // Reject invalid ports, unbracketed IPv6, and invalid path characters / percent-encoding
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://dns.google:0/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://dns.google:65536/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://dns.google:70000/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://dns.google:-1/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://dns.google:abc/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://dns.google:/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://[2606:4700:4700::1111]:0/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://[2606:4700:4700::1111]:70000/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://2606:4700:4700::1111/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://[2606:4700:4700::1111/dns-query"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://dns.google/bad path"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://dns.google/bad%ZZ"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https://"))
        XCTAssertFalse(VdpiFormatters.isValidDnsInput("https:///dns-query"))
    }

    func testRedactHttpsUrlsPreservesBalancedParenthesesAndOuterDelimiters() {
        // Balanced parentheses inside the URL path are fully redacted (no trailing `)` leak).
        XCTAssertEqual(
            TunnelManager.redactHttpsUrls(
                in: "failed for https://dns.nextdns.io/profile(iphone)"
            ),
            "failed for https://dns.nextdns.io/[redacted]"
        )

        // Balanced parentheses inside the URL path wrapped in outer sentence parentheses.
        XCTAssertEqual(
            TunnelManager.redactHttpsUrls(
                in: "error for url (https://dns.nextdns.io/profile(iphone)): timeout"
            ),
            "error for url (https://dns.nextdns.io/[redacted]): timeout"
        )

        // Nested balanced parentheses in query string wrapped in outer parentheses.
        XCTAssertEqual(
            TunnelManager.redactHttpsUrls(
                in: "probe (https://dns.example.com/dns-query?device=(work(1))): reset"
            ),
            "probe (https://dns.example.com/[redacted]): reset"
        )

        // IPv6 bracketed URL wrapped in outer square brackets.
        XCTAssertEqual(
            TunnelManager.redactHttpsUrls(
                in: "endpoint [https://[2606:4700:4700::1111]/secret-profile] unreachable"
            ),
            "endpoint [https://[2606:4700:4700::1111]/[redacted]] unreachable"
        )
    }

    func testSettingsLanguageBackwardCompatibleDecodeAndRoundTrip() throws {
        // Default language is `.system`.
        XCTAssertEqual(VdpiSettings().language, .system)

        // Older persisted JSON without `"language"` key must decode cleanly to `.system`.
        let legacyJson = """
        {
            "desyncMode": "combo",
            "chunkSize": 10,
            "dnsAddr": "1.1.1.1",
            "enableDoh": true,
            "ipv4Only": false,
            "blockQuic": true,
            "mtu": 4064,
            "bypassDomains": [],
            "onDemandEnabled": false,
            "theme": "dark"
        }
        """
        let legacyDecoded = try JSONDecoder().decode(
            VdpiSettings.self,
            from: try XCTUnwrap(legacyJson.data(using: .utf8))
        )
        XCTAssertEqual(legacyDecoded.language, .system)
        XCTAssertEqual(legacyDecoded.theme, .dark)

        // Round-trip every AppLanguage value via VdpiSettings and JSON import.
        for lang in AppLanguage.allCases {
            var settings = VdpiSettings(theme: .light, language: lang)
            let data = try JSONEncoder().encode(settings)
            let dict = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
            XCTAssertEqual(dict["language"] as? String, lang.rawValue)

            let decoded = try JSONDecoder().decode(VdpiSettings.self, from: data)
            XCTAssertEqual(decoded.language, lang)

            // Changing only language must never trigger a tunnel reload.
            settings.language = (lang == .tr) ? .en : .tr
            XCTAssertFalse(settings.requiresTunnelReload(comparedTo: decoded))
            XCTAssertTrue(settings.changedFieldLabels(comparedTo: decoded).isEmpty)
        }

        // Import JSON containing only `"language": "tr"` is accepted and preserved.
        let imported = try TunnelManager.parseImportedSettings("{\"language\":\"tr\"}")
        XCTAssertEqual(imported.language, .tr)
    }

    func testLocalizationResolutionAndTurkishEnglishLookups() {
        // `.system` resolves Turkish when first preferred language starts with "tr", else English.
        XCTAssertEqual(L10n.resolve(.system, preferredLanguages: ["tr-TR", "en-US"]), .tr)
        XCTAssertEqual(L10n.resolve(.system, preferredLanguages: ["TR", "en"]), .tr)
        XCTAssertEqual(L10n.resolve(.system, preferredLanguages: ["en-US", "tr-TR"]), .en)
        XCTAssertEqual(L10n.resolve(.system, preferredLanguages: ["de-DE"]), .en)
        XCTAssertEqual(L10n.resolve(.system, preferredLanguages: []), .en)

        // Explicit overrides ignore system preferredLanguages.
        XCTAssertEqual(L10n.resolve(.en, preferredLanguages: ["tr-TR"]), .en)
        XCTAssertEqual(L10n.resolve(.tr, preferredLanguages: ["en-US"]), .tr)

        let en = L10n.catalog(for: .en)
        let tr = L10n.catalog(for: .tr)

        XCTAssertEqual(en.tabTunnel, "Tunnel")
        XCTAssertEqual(tr.tabTunnel, "Tünel")
        XCTAssertEqual(en.tabSettings, "Settings")
        XCTAssertEqual(tr.tabSettings, "Ayarlar")
        XCTAssertEqual(en.buttonConnect, "Connect")
        XCTAssertEqual(tr.buttonConnect, "Bağlan")
        XCTAssertEqual(en.buttonDisconnect, "Disconnect")
        XCTAssertEqual(tr.buttonDisconnect, "Bağlantıyı Kes")
        XCTAssertEqual(en.sectionLanguage, "Language")
        XCTAssertEqual(tr.sectionLanguage, "Dil")
        XCTAssertEqual(en.diagnosticsTitle, "Diagnostics")
        XCTAssertEqual(tr.diagnosticsTitle, "Tanılama")
        XCTAssertEqual(en.intentConnected, "Connected vdpi.")
        XCTAssertEqual(tr.intentConnected, "vdpi bağlandı.")
        XCTAssertEqual(tr.doctorCheckName("DNS Ring"), "DNS Halkası")
        XCTAssertEqual(tr.doctorCheckName("Discord API"), "Discord API")

        // AppLanguage endonyms and System/Sistem label.
        XCTAssertEqual(AppLanguage.system.label(in: .en), "System")
        XCTAssertEqual(AppLanguage.system.label(in: .tr), "Sistem")
        XCTAssertEqual(AppLanguage.en.label(in: .tr), "English")
        XCTAssertEqual(AppLanguage.tr.label(in: .en), "Türkçe")

        // Localized model/formatter helpers.
        XCTAssertEqual(ThemePreference.dark.label(in: .tr), "Koyu")
        XCTAssertEqual(ThemePreference.light.label(in: .tr), "Açık")
        XCTAssertEqual(DesyncMode.combo.label(in: .tr), "Kombo")
        XCTAssertEqual(VdpiFormatters.formatStageLabel("DirectPassthrough", language: .tr), "Doğrudan Geçiş")
        XCTAssertEqual(VdpiFormatters.formatStageLabel("DirectPassthrough", language: .en), "Passthrough")
        XCTAssertEqual(TunnelPhase.connected.label(in: .tr), "Korumalı")

        let baseline = VdpiSettings(desyncMode: .combo, chunkSize: 10, bypassDomains: [])
        let changed = VdpiSettings(desyncMode: .split, chunkSize: 16, bypassDomains: ["example.com"])
        XCTAssertEqual(
            changed.changedFieldLabels(comparedTo: baseline, language: .tr),
            ["Mod", "Parça", "İstisna"]
        )
        XCTAssertEqual(
            changed.pendingChangeSummary(comparedToApplied: baseline.toNativeConfig(), language: .tr),
            "Mod, Parça, İstisna"
        )
    }
}
