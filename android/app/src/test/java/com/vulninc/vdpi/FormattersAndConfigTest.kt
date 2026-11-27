package com.vulninc.vdpi

import com.vulninc.vdpi.data.SettingsRepository
import com.vulninc.vdpi.data.SplitTunnelMode
import com.vulninc.vdpi.data.ThemePreference
import com.vulninc.vdpi.data.UpdateChecker
import com.vulninc.vdpi.data.VdpiSettings
import com.vulninc.vdpi.engine.DesyncMode
import com.vulninc.vdpi.engine.DoctorCheck
import com.vulninc.vdpi.engine.DoctorReport
import com.vulninc.vdpi.engine.NativeEngine
import com.vulninc.vdpi.engine.NativeEngineConfig
import com.vulninc.vdpi.engine.TelemetrySnapshot
import com.vulninc.vdpi.ui.appendThroughputSample
import com.vulninc.vdpi.ui.buildDiagnosticsReport
import com.vulninc.vdpi.ui.computeSettingsChangeSummary
import com.vulninc.vdpi.vpn.TunnelPhase
import com.vulninc.vdpi.vpn.TunnelRuntimeSnapshot
import com.vulninc.vdpi.util.formatBytes
import com.vulninc.vdpi.util.formatEventTime
import com.vulninc.vdpi.util.formatStageLabel
import com.vulninc.vdpi.util.formatStageShort
import com.vulninc.vdpi.util.formatUptime
import com.vulninc.vdpi.util.isValidBypassDomain
import com.vulninc.vdpi.util.isValidDnsInput
import com.vulninc.vdpi.util.sanitizeDomainInput
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FormattersAndConfigTest {

    @Test
    fun formatBytesScalesAcrossUnits() {
        assertEquals("0 B", formatBytes(0))
        assertEquals("512 B", formatBytes(512))
        assertEquals("1.5 KB", formatBytes(1536))
        assertEquals("2.0 MB", formatBytes(2L * 1024L * 1024L))
        assertEquals("1.50 GB", formatBytes((1.5 * 1024 * 1024 * 1024).toLong()))
    }

    @Test
    fun formatUptimeFormatsTabularClock() {
        assertEquals("00:00:00", formatUptime(0))
        assertEquals("00:01:09", formatUptime(69))
        assertEquals("02:05:30", formatUptime(2 * 3600 + 5 * 60 + 30))
    }

    @Test
    fun formatStageShortMapsKnownStrategies() {
        assertEquals("Stage 1 · Combo", formatStageShort(1, "ComboMultiRecord"))
        assertEquals("Stage 2 · OOB SNI", formatStageShort(2, "OobSniDesync"))
        assertEquals("Stage 5 · Deep Storm", formatStageShort(5, "DeepRecordStorm"))
    }

    @Test
    fun formatStageLabelMapsKnownStrategies() {
        assertEquals("Combo", formatStageLabel("ComboMultiRecord"))
        assertEquals("OOB SNI", formatStageLabel("OobSniDesync"))
        assertEquals("Multi + OOB", formatStageLabel("MultiRecordOob"))
        assertEquals("Fine Fragment", formatStageLabel("FineFragment"))
        assertEquals("Deep Storm", formatStageLabel("DeepRecordStorm"))
        assertEquals("Slow SNI", formatStageLabel("SlowSniSlice"))
        assertEquals("Passthrough", formatStageLabel("DirectPassthrough"))
    }

    @Test
    fun formatStageLabelFallsBackVerbatimForUnknownAndBlankInputs() {
        assertEquals("SplitOnly", formatStageLabel("SplitOnly"))
        assertEquals("TlsRecord", formatStageLabel("TlsRecord"))
        assertEquals("Combo", formatStageLabel("Combo"))
        assertEquals("OobTlsRecord", formatStageLabel("OobTlsRecord"))
        assertEquals("", formatStageLabel(""))
        assertEquals("   ", formatStageLabel("   "))
    }

    @Test
    fun sanitizeDomainStripsSchemeAndPathCaseInsensitively() {
        assertEquals("example.com", sanitizeDomainInput("  https://Example.COM/foo/bar "))
        assertEquals("example.com", sanitizeDomainInput("HTTPS://EXAMPLE.COM/path?q=1"))
        assertEquals("*.mybank.com", sanitizeDomainInput("*.MyBank.com:443."))
        assertEquals("instagram.com", sanitizeDomainInput("HTTP://INSTAGRAM.COM"))
    }

    @Test
    fun validatesDnsAndBypassDomainInputs() {
        assertTrue(isValidDnsInput("1.1.1.1"))
        assertTrue(isValidDnsInput("9.9.9.9"))
        assertTrue(isValidDnsInput("2606:4700:4700::1111"))
        assertTrue(isValidDnsInput("[2606:4700:4700::1111]"))
        assertTrue(isValidDnsInput("2001:4860:4860:0:0:0:0:8888"))
        assertTrue(isValidDnsInput("https://dns.quad9.net/dns-query"))
        assertTrue(isValidDnsInput("https://dns.quad9.net:443/dns-query"))
        assertFalse(isValidDnsInput("foo bar"))
        assertFalse(isValidDnsInput("999.999.999.999"))
        assertFalse(isValidDnsInput("http://1.1.1.1/dns-query"))
        assertFalse(isValidDnsInput("https://dns.quad9.net:0/dns-query"))
        assertFalse(isValidDnsInput("https://dns.quad9.net:70000/dns-query"))
        assertFalse(isValidDnsInput("https://dns.quad9.net:-1/dns-query"))
        assertFalse(isValidDnsInput("[2606:4700:4700::1111"))
        assertFalse(isValidDnsInput("2606:4700:4700::1111]"))
        assertFalse(isValidDnsInput(":2606:4700:4700::1111"))
        assertFalse(isValidDnsInput("2606:4700:4700::1111:"))
        assertFalse(isValidDnsInput("1:2:3:4:5:6:7"))
        assertFalse(isValidDnsInput("1:2:3:4:5:6:7:8::"))
        assertFalse(isValidDnsInput("::"))
        assertFalse(isValidDnsInput("2606::4700::1111"))
        assertFalse(isValidDnsInput("2606:::1111"))

        assertTrue(isValidBypassDomain("example.com"))
        assertTrue(isValidBypassDomain("*.bank.gov.tr"))
        assertTrue(isValidBypassDomain("HTTPS://Sub.Domain.Org/page"))
        assertFalse(isValidBypassDomain("not a domain"))
        assertFalse(isValidBypassDomain("singlelabel"))
        assertFalse(isValidBypassDomain(""))
    }

    @Test
    fun formatEventTimeHandlesZeroAndValidTimestamps() {
        assertEquals("--:--:--", formatEventTime(0L))
        assertTrue(formatEventTime(1700000000000L).matches(Regex("^\\d{2}:\\d{2}:\\d{2}$")))
    }

    @Test
    fun nativeConfigSerializesMatchingRustSchema() {
        val cfg = NativeEngineConfig(
            mode = DesyncMode.TLS_RECORD,
            chunkSize = 6,
            dnsAddr = "9.9.9.9",
            enableDoh = true,
            ipv4Only = true,
            blockQuic = false,
            bypassDomains = listOf("*.bank.example"),
        )
        val encoded = NativeEngine.encodeConfig(cfg)
        assertTrue(encoded.contains("\"mode\":\"tls-record\""))
        assertTrue(encoded.contains("\"chunk_size\":6"))
        assertTrue(encoded.contains("\"dns_addr\":\"9.9.9.9\""))
        assertTrue(encoded.contains("\"ipv4_only\":true"))
        assertTrue(encoded.contains("\"block_quic\":false"))
        assertTrue(encoded.contains("\"bypass_domains\":[\"*.bank.example\"]"))
    }

    @Test
    fun snapshotDecodesRustTelemetryJson() {
        val raw = """
            {
              "running": true,
              "uptime_secs": 125,
              "active_connections": 7,
              "total_connections": 42,
              "bytes_tx": 10240,
              "bytes_rx": 81920,
              "tls_handshakes": 19,
              "auto_heal_escalations": 1,
              "dns_queries": 31,
              "quic_blocked": 4,
              "udp_flows_active": 2,
              "learned_hosts": 12,
              "stage_number": 2,
              "stage_label": "OobSniDesync",
              "dns_addr": "1.1.1.1",
              "doh_enabled": true,
              "events": [{"ts_ms": 1700000000000, "level": "info", "tag": "tunnel", "message": "started"}]
            }
        """.trimIndent()
        val snap = NativeEngine.decodeSnapshot(raw)
        assertTrue(snap.running)
        assertEquals(125L, snap.uptimeSecs)
        assertEquals(31L, snap.dnsQueries)
        assertEquals(4L, snap.quicBlocked)
        assertEquals(2L, snap.udpFlowsActive)
        assertEquals(2, snap.stageNumber)
        assertEquals("OobSniDesync", snap.stageLabel)
        assertEquals(1, snap.events.size)
        assertEquals("started", snap.events.first().message)
    }

    @Test
    fun changeSummaryIgnoresThemeOnlyEdits() {
        val baseline = VdpiSettings()
        assertEquals(
            emptyList<String>(),
            computeSettingsChangeSummary(baseline.copy(theme = ThemePreference.DARK), baseline),
        )
        assertEquals(
            emptyList<String>(),
            computeSettingsChangeSummary(baseline.copy(theme = ThemePreference.LIGHT), baseline),
        )
        assertEquals(
            emptyList<String>(),
            computeSettingsChangeSummary(baseline.copy(theme = ThemePreference.SYSTEM), baseline),
        )
    }

    @Test
    fun defaultThemeAndWireFallbackUseSystem() {
        assertEquals(ThemePreference.SYSTEM, VdpiSettings().theme)
        assertEquals(ThemePreference.SYSTEM, ThemePreference.fromWire(null))
        assertEquals(ThemePreference.SYSTEM, ThemePreference.fromWire("unknown"))
        assertEquals(ThemePreference.SYSTEM, ThemePreference.fromWire("system"))
        assertEquals(ThemePreference.DARK, ThemePreference.fromWire("dark"))
        assertEquals(ThemePreference.LIGHT, ThemePreference.fromWire("light"))
    }

    @Test
    fun desyncModeSummariesMatchCrossPlatformCopy() {
        assertEquals(
            "4-record TLS split + adaptive 7-stage auto-heal",
            DesyncMode.COMBO.summary,
        )
        assertEquals(
            "Split ClientHello across two RFC TLS records",
            DesyncMode.TLS_RECORD.summary,
        )
        assertEquals(
            "Single outer TLS record sliced at SNI boundaries",
            DesyncMode.FRAGMENT.summary,
        )
        assertEquals(
            "Initial chunk-byte TCP split on first flight",
            DesyncMode.SPLIT.summary,
        )
    }

    @Test
    fun changeSummaryNormalizesDnsWhitespaceAndBypassOrder() {
        val baseline = VdpiSettings(
            dnsAddr = "1.1.1.1",
            bypassDomains = listOf("a.com", "b.com"),
        )
        assertEquals(
            emptyList<String>(),
            computeSettingsChangeSummary(baseline.copy(dnsAddr = " 1.1.1.1 "), baseline),
        )
        assertEquals(
            emptyList<String>(),
            computeSettingsChangeSummary(baseline, baseline.copy(dnsAddr = " 1.1.1.1 ")),
        )
        assertEquals(
            emptyList<String>(),
            computeSettingsChangeSummary(
                baseline.copy(bypassDomains = listOf("b.com", "a.com")),
                baseline,
            ),
        )
    }

    @Test
    fun changeSummaryReportsExpectedLabelsForEachField() {
        val baseline = VdpiSettings(
            desyncMode = DesyncMode.COMBO,
            chunkSize = 10,
            dnsAddr = "1.1.1.1",
            enableDoh = true,
            ipv4Only = false,
            blockQuic = true,
            bypassDomains = listOf("a.com", "b.com"),
            splitTunnelMode = SplitTunnelMode.BYPASS_SELECTED,
            splitPackages = emptySet(),
            theme = ThemePreference.DARK,
        )

        assertEquals(
            listOf("Mode"),
            computeSettingsChangeSummary(baseline.copy(desyncMode = DesyncMode.TLS_RECORD), baseline),
        )
        assertEquals(
            listOf("Chunk"),
            computeSettingsChangeSummary(baseline.copy(chunkSize = 16), baseline),
        )
        assertEquals(
            listOf("DNS"),
            computeSettingsChangeSummary(baseline.copy(dnsAddr = "9.9.9.9"), baseline),
        )
        assertEquals(
            listOf("DoH"),
            computeSettingsChangeSummary(baseline.copy(enableDoh = false), baseline),
        )
        assertEquals(
            listOf("IPv4"),
            computeSettingsChangeSummary(baseline.copy(ipv4Only = true), baseline),
        )
        assertEquals(
            listOf("QUIC"),
            computeSettingsChangeSummary(baseline.copy(blockQuic = false), baseline),
        )
        assertEquals(
            listOf("Bypass"),
            computeSettingsChangeSummary(
                baseline.copy(bypassDomains = listOf("a.com", "b.com", "c.com")),
                baseline,
            ),
        )
        assertEquals(
            listOf("Apps"),
            computeSettingsChangeSummary(
                baseline.copy(splitTunnelMode = SplitTunnelMode.ONLY_SELECTED),
                baseline,
            ),
        )
        assertEquals(
            listOf("Apps"),
            computeSettingsChangeSummary(
                baseline.copy(splitPackages = setOf("com.example.app")),
                baseline,
            ),
        )

        val allChanged = baseline.copy(
            desyncMode = DesyncMode.FRAGMENT,
            chunkSize = 20,
            dnsAddr = "8.8.8.8",
            enableDoh = false,
            ipv4Only = true,
            blockQuic = false,
            bypassDomains = listOf("c.com"),
            splitTunnelMode = SplitTunnelMode.ONLY_SELECTED,
            splitPackages = setOf("com.example.app"),
            theme = ThemePreference.LIGHT,
        )
        val combined = computeSettingsChangeSummary(allChanged, baseline)
        assertEquals(8, combined.size)
        assertEquals(
            setOf("Mode", "Chunk", "DNS", "DoH", "IPv4", "QUIC", "Bypass", "Apps"),
            combined.toSet(),
        )
    }

    @Test
    fun changeSummaryClearsWhenRevertedToBaseline() {
        val baseline = VdpiSettings(
            desyncMode = DesyncMode.COMBO,
            dnsAddr = "1.1.1.1",
            bypassDomains = listOf("a.com", "b.com"),
            splitPackages = setOf("com.example.keep"),
        )
        val edited = baseline.copy(
            desyncMode = DesyncMode.SPLIT,
            dnsAddr = "9.9.9.9",
            bypassDomains = listOf("a.com"),
            splitPackages = setOf("com.example.keep", "com.example.other"),
        )
        assertEquals(
            setOf("Mode", "DNS", "Bypass", "Apps"),
            computeSettingsChangeSummary(edited, baseline).toSet(),
        )

        val reverted = edited.copy(
            desyncMode = baseline.desyncMode,
            dnsAddr = " 1.1.1.1 ",
            bypassDomains = listOf("b.com", "a.com"),
            splitPackages = baseline.splitPackages,
        )
        assertEquals(emptyList<String>(), computeSettingsChangeSummary(reverted, baseline))
    }

    @Test
    fun updateCheckerIsNewerVersionMatrix() {
        assertTrue(UpdateChecker.isNewerVersion("v0.4.1", "0.4.0"))
        assertTrue(UpdateChecker.isNewerVersion("V1.2.3", "1.2.2"))
        assertTrue(UpdateChecker.isNewerVersion("V1.2.3", "V1.2.2"))
        assertTrue(UpdateChecker.isNewerVersion("V1.2.3", "V1.2.2-debug"))
        assertTrue(UpdateChecker.isNewerVersion("0.10.0", "0.9.9"))
        assertTrue(UpdateChecker.isNewerVersion("1.0.0", "0.99.99"))
        assertTrue(UpdateChecker.isNewerVersion("v0.4.1", "0.4.0-debug"))

        // Equal versions
        assertFalse(UpdateChecker.isNewerVersion("0.4.0", "0.4.0"))
        assertFalse(UpdateChecker.isNewerVersion("v0.4.0", "0.4.0"))
        assertFalse(UpdateChecker.isNewerVersion("V1.2.3", "1.2.3"))
        assertFalse(UpdateChecker.isNewerVersion("0.4.0", "0.4.0-debug"))

        // Older versions
        assertFalse(UpdateChecker.isNewerVersion("0.3.9", "0.4.0"))
        assertFalse(UpdateChecker.isNewerVersion("v0.3.4", "0.4.0"))
        assertFalse(UpdateChecker.isNewerVersion("V1.2.2", "V1.2.3"))
        assertFalse(UpdateChecker.isNewerVersion("0.9.9", "0.10.0"))

        // Prerelease and build metadata rejected
        assertFalse(UpdateChecker.isNewerVersion("v0.5.0-beta.1", "0.4.0"))
        assertFalse(UpdateChecker.isNewerVersion("0.5.0-rc.1", "0.4.0"))
        assertFalse(UpdateChecker.isNewerVersion("0.4.1+20260101", "0.4.0"))

        // Garbage / malformed versions rejected
        assertFalse(UpdateChecker.isNewerVersion("", "0.4.0"))
        assertFalse(UpdateChecker.isNewerVersion("invalid", "0.4.0"))
        assertFalse(UpdateChecker.isNewerVersion("0.4", "0.3.0"))
        assertFalse(UpdateChecker.isNewerVersion("0.4.1.0", "0.4.0"))
        assertFalse(UpdateChecker.isNewerVersion("v0.a.1", "0.4.0"))
        assertFalse(UpdateChecker.isNewerVersion("-1.0.0", "0.4.0"))
        assertFalse(UpdateChecker.isNewerVersion("0.4.1", "not-a-version"))
        assertFalse(UpdateChecker.isNewerVersion("0.4.1", ""))
    }

    @Test
    fun settingsJsonExportImportRoundtripAndSanitization() {
        val original = VdpiSettings(
            desyncMode = DesyncMode.TLS_RECORD,
            chunkSize = 18,
            dnsAddr = "9.9.9.9",
            enableDoh = false,
            ipv4Only = true,
            blockQuic = false,
            bypassDomains = listOf("*.bank.example", "portal.gov.tr"),
            splitTunnelMode = SplitTunnelMode.ONLY_SELECTED,
            splitPackages = setOf("com.example.alpha", "org.example.beta"),
            theme = ThemePreference.DARK,
        )

        val encoded = SettingsRepository.exportSettingsJson(original)
        val parsed = SettingsRepository.parseSettingsJson(encoded)
        assertTrue(parsed.isSuccess)
        assertEquals(original, parsed.getOrThrow())

        val messy = """
            {
              "version": 1,
              "desync_mode": "fragment",
              "chunk_size": 999,
              "dns_addr": " 1.1.1.1 ",
              "enable_doh": true,
              "ipv4_only": false,
              "block_quic": true,
              "bypass_domains": ["  HTTPS://Example.COM/path ", "not a domain", "example.com"],
              "split_tunnel_mode": "bypass_selected",
              "split_packages": ["com.example.good", "invalid package"],
              "theme": "light"
            }
        """.trimIndent()
        val sanitized = SettingsRepository.parseSettingsJson(messy).getOrThrow()
        assertEquals(DesyncMode.FRAGMENT, sanitized.desyncMode)
        assertEquals(64, sanitized.chunkSize)
        assertEquals("1.1.1.1", sanitized.dnsAddr)
        assertEquals(listOf("example.com"), sanitized.bypassDomains)
        assertEquals(setOf("com.example.good"), sanitized.splitPackages)
        assertEquals(ThemePreference.LIGHT, sanitized.theme)

        val lowChunk = """{"desync_mode":"split","chunk_size":0,"dns_addr":"8.8.8.8"}"""
        assertEquals(1, SettingsRepository.parseSettingsJson(lowChunk).getOrThrow().chunkSize)
    }

    @Test
    fun settingsJsonRejectsCorruptAndInvalidPayloads() {
        assertTrue(SettingsRepository.parseSettingsJson("").isFailure)
        assertTrue(SettingsRepository.parseSettingsJson("   ").isFailure)
        assertTrue(SettingsRepository.parseSettingsJson("{not valid json").isFailure)
        assertTrue(SettingsRepository.parseSettingsJson("[]").isFailure)
        assertTrue(SettingsRepository.parseSettingsJson("{}").isFailure)
        assertTrue(SettingsRepository.parseSettingsJson("""{"unrelated":"value"}""").isFailure)
        assertTrue(
            SettingsRepository.parseSettingsJson(
                """{"version":99,"desync_mode":"combo","dns_addr":"1.1.1.1"}"""
            ).isFailure
        )
        assertTrue(
            SettingsRepository.parseSettingsJson(
                """{"desync_mode":"combo","dns_addr":"999.999.999.999"}"""
            ).isFailure
        )
        assertTrue(
            SettingsRepository.parseSettingsJson(
                """{"desync_mode":"combo","dns_addr":"http://1.1.1.1/dns-query"}"""
            ).isFailure
        )
        assertTrue(
            SettingsRepository.parseSettingsJson(
                """{"desync_mode":"unknown-mode","dns_addr":"1.1.1.1"}"""
            ).isFailure
        )
        assertTrue(
            SettingsRepository.parseSettingsJson(
                """{"desync_mode":"combo","dns_addr":"1.1.1.1","split_tunnel_mode":"weird"}"""
            ).isFailure
        )
        assertTrue(
            SettingsRepository.parseSettingsJson(
                """{"desync_mode":"combo","dns_addr":"1.1.1.1","theme":"neon"}"""
            ).isFailure
        )
        assertTrue(
            SettingsRepository.parseSettingsJson(
                """{"desync_mode":"combo","dns_addr":"1.1.1.1","theme":""}"""
            ).isFailure
        )
        assertTrue(
            SettingsRepository.parseSettingsJson(
                """{"version":{},"desync_mode":"combo","dns_addr":"1.1.1.1"}"""
            ).isFailure
        )
        assertTrue(
            SettingsRepository.parseSettingsJson(
                """{"version":[1],"desync_mode":"combo","dns_addr":"1.1.1.1"}"""
            ).isFailure
        )
        assertTrue(
            SettingsRepository.parseSettingsJson(
                """{"version":"1","desync_mode":"combo","dns_addr":"1.1.1.1"}"""
            ).isFailure
        )
        assertTrue(
            SettingsRepository.parseSettingsJson(
                """{"version":null,"desync_mode":"combo","dns_addr":"1.1.1.1"}"""
            ).isFailure
        )
        assertTrue(
            SettingsRepository.parseSettingsJson(
                """{"version":true,"desync_mode":"combo","dns_addr":"1.1.1.1"}"""
            ).isFailure
        )
    }

    @Test
    fun nativeConfigSerializesCachePath() {
        val cfg = NativeEngineConfig(
            cachePath = "/data/user/0/com.vulninc.vdpi/files/adaptive-cache.json",
        )
        val encoded = NativeEngine.encodeConfig(cfg)
        assertTrue(
            encoded.contains(
                "\"cache_path\":\"/data/user/0/com.vulninc.vdpi/files/adaptive-cache.json\""
            )
        )
    }

    @Test
    fun throughputRingCapsAt24SamplesAndClampsNegatives() {
        var ring = emptyList<Long>()
        for (i in 1L..30L) {
            ring = appendThroughputSample(ring, i * 100L)
        }
        assertEquals(24, ring.size)
        assertEquals(700L, ring.first())
        assertEquals(3000L, ring.last())

        val clamped = appendThroughputSample(ring, -500L)
        assertEquals(24, clamped.size)
        assertEquals(0L, clamped.last())
    }

    @Test
    fun diagnosticsReportFormatsAndRedactsSensitiveFields() {
        val settings = VdpiSettings(
            desyncMode = DesyncMode.COMBO,
            chunkSize = 10,
            dnsAddr = "https://dns.custom.example/secret-token-123",
            enableDoh = true,
            ipv4Only = false,
            blockQuic = true,
            bypassDomains = listOf("private-bank.example", "secret.internal.org"),
            splitTunnelMode = SplitTunnelMode.BYPASS_SELECTED,
            splitPackages = setOf("com.secret.wallet"),
        )
        val runtime = TunnelRuntimeSnapshot(
            phase = TunnelPhase.CONNECTED,
            telemetry = TelemetrySnapshot(
                running = true,
                uptimeSecs = 95,
                stageNumber = 2,
                stageLabel = "OobSniDesync",
                dnsAddr = settings.dnsAddr,
                dohEnabled = settings.enableDoh,
            ),
        )
        val report = DoctorReport(
            ok = true,
            checks = listOf(
                DoctorCheck(
                    name = "DoH",
                    target = "1.1.1.1",
                    passed = true,
                    latencyMs = 28L,
                    detail = "HTTP/2 OK",
                ),
            ),
        )

        val text = buildDiagnosticsReport(
            appVersion = "0.4.0",
            engineVersion = "0.4.0",
            settings = settings,
            runtime = runtime,
            doctorReport = report,
            androidRelease = "15",
            androidSdk = 35,
        )

        assertTrue(text.contains("App Version: v0.4.0"))
        assertTrue(text.contains("Desync Mode: Combo (combo), chunk=10"))
        assertTrue(text.contains("https://dns.custom.example/<redacted>"))
        assertTrue(text.contains("QUIC Blocking: enabled"))
        assertTrue(text.contains("Bypass Domains: 2 configured (redacted)"))
        assertTrue(text.contains("Split Tunnel: Bypass selected (1 apps, redacted)"))
        assertTrue(text.contains("- [PASS] DoH (1.1.1.1): 28 ms - HTTP/2 OK"))
        assertFalse(text.contains("secret-token-123"))
        assertFalse(text.contains("private-bank.example"))
        assertFalse(text.contains("com.secret.wallet"))
    }
}
