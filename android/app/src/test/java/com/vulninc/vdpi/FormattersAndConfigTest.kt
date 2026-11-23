package com.vulninc.vdpi

import com.vulninc.vdpi.data.SplitTunnelMode
import com.vulninc.vdpi.data.ThemePreference
import com.vulninc.vdpi.data.VdpiSettings
import com.vulninc.vdpi.engine.DesyncMode
import com.vulninc.vdpi.engine.NativeEngine
import com.vulninc.vdpi.engine.NativeEngineConfig
import com.vulninc.vdpi.ui.computeSettingsChangeSummary
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
        assertTrue(isValidDnsInput("https://dns.quad9.net/dns-query"))
        assertFalse(isValidDnsInput("foo bar"))
        assertFalse(isValidDnsInput("999.999.999.999"))
        assertFalse(isValidDnsInput("http://1.1.1.1/dns-query"))

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
}
