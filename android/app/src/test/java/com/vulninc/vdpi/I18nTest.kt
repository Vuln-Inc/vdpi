package com.vulninc.vdpi

import com.vulninc.vdpi.data.AppLanguage
import com.vulninc.vdpi.data.SettingsImportException
import com.vulninc.vdpi.data.SettingsRepository
import com.vulninc.vdpi.data.SplitTunnelMode
import com.vulninc.vdpi.data.ThemePreference
import com.vulninc.vdpi.data.VdpiSettings
import com.vulninc.vdpi.engine.DesyncMode
import com.vulninc.vdpi.engine.DoctorCheck
import com.vulninc.vdpi.engine.DoctorReport
import com.vulninc.vdpi.engine.TelemetrySnapshot
import com.vulninc.vdpi.ui.buildDiagnosticsReport
import com.vulninc.vdpi.ui.computeSettingsChangeSummary
import com.vulninc.vdpi.ui.i18n.EnglishStrings
import com.vulninc.vdpi.ui.i18n.TurkishStrings
import com.vulninc.vdpi.ui.i18n.VdpiStrings
import com.vulninc.vdpi.ui.screens.splitSummary
import com.vulninc.vdpi.util.formatStageLabel
import com.vulninc.vdpi.util.formatStageShort
import com.vulninc.vdpi.vpn.TunnelPhase
import com.vulninc.vdpi.vpn.TunnelRuntimeSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Modifier
import java.util.Locale

class I18nTest {

    @Test
    fun appLanguageDefaultsToSystemAndParsesCodes() {
        assertEquals(AppLanguage.SYSTEM, VdpiSettings().language)
        assertEquals("system", AppLanguage.SYSTEM.code)
        assertEquals("en", AppLanguage.EN.code)
        assertEquals("tr", AppLanguage.TR.code)

        assertEquals(AppLanguage.SYSTEM, AppLanguage.fromCode(null))
        assertEquals(AppLanguage.SYSTEM, AppLanguage.fromCode(""))
        assertEquals(AppLanguage.SYSTEM, AppLanguage.fromCode("unknown"))
        assertEquals(AppLanguage.SYSTEM, AppLanguage.fromCode("system"))
        assertEquals(AppLanguage.EN, AppLanguage.fromCode("en"))
        assertEquals(AppLanguage.EN, AppLanguage.fromCode("  EN "))
        assertEquals(AppLanguage.TR, AppLanguage.fromCode("tr"))
        assertEquals(AppLanguage.TR, AppLanguage.fromCode("TR"))
    }

    @Test
    fun resolveAndForLanguageRespectExplicitAndSystemLocales() {
        val trLocale = Locale("tr", "TR")
        val trLangOnly = Locale("tr")
        val enLocale = Locale.US
        val deLocale = Locale.GERMANY

        assertSame(EnglishStrings, VdpiStrings.resolve(AppLanguage.EN, trLocale))
        assertSame(TurkishStrings, VdpiStrings.resolve(AppLanguage.TR, enLocale))
        assertSame(TurkishStrings, VdpiStrings.resolve(AppLanguage.SYSTEM, trLocale))
        assertSame(TurkishStrings, VdpiStrings.resolve(AppLanguage.SYSTEM, trLangOnly))
        assertSame(EnglishStrings, VdpiStrings.resolve(AppLanguage.SYSTEM, enLocale))
        assertSame(EnglishStrings, VdpiStrings.resolve(AppLanguage.SYSTEM, deLocale))

        assertSame(TurkishStrings, VdpiStrings.forLanguage(AppLanguage.TR, enLocale))
        assertSame(EnglishStrings, VdpiStrings.forLanguage(AppLanguage.EN, trLocale))
    }

    @Test
    fun languageOnlyChangesDoNotRequireTunnelReconnect() {
        val baseline = VdpiSettings()
        assertEquals(
            emptyList<String>(),
            computeSettingsChangeSummary(baseline.copy(language = AppLanguage.TR), baseline),
        )
        assertEquals(
            emptyList<String>(),
            computeSettingsChangeSummary(baseline.copy(language = AppLanguage.EN), baseline),
        )
        assertEquals(
            emptyList<String>(),
            computeSettingsChangeSummary(baseline.copy(language = AppLanguage.SYSTEM), baseline),
        )
    }

    @Test
    fun settingsBackupRoundtripsLanguageAndRejectsInvalidValues() {
        val original = VdpiSettings(
            theme = ThemePreference.DARK,
            language = AppLanguage.TR,
        )
        val encoded = SettingsRepository.exportSettingsJson(original)
        assertTrue(encoded.contains("\"language\": \"tr\""))

        val parsed = SettingsRepository.parseSettingsJson(encoded)
        assertTrue(parsed.isSuccess)
        assertEquals(AppLanguage.TR, parsed.getOrThrow().language)

        val legacyPayload = """{"desync_mode":"combo","dns_addr":"1.1.1.1"}"""
        val legacyParsed = SettingsRepository.parseSettingsJson(legacyPayload)
        assertTrue(legacyParsed.isSuccess)
        assertEquals(AppLanguage.SYSTEM, legacyParsed.getOrThrow().language)

        val invalidLang = """{"desync_mode":"combo","dns_addr":"1.1.1.1","language":"fr"}"""
        assertTrue(SettingsRepository.parseSettingsJson(invalidLang).isFailure)
    }

    @Test
    fun allStringFieldsInEnglishAndTurkishAreNonBlankAndHaveNoEmDashes() {
        val stringFields = VdpiStrings::class.java.declaredFields.filter { field ->
            !Modifier.isStatic(field.modifiers) && field.type == String::class.java
        }
        assertTrue("Expected VdpiStrings to have String fields", stringFields.size > 100)

        for (field in stringFields) {
            field.isAccessible = true
            val en = field.get(EnglishStrings) as String
            val tr = field.get(TurkishStrings) as String
            assertTrue("EnglishStrings.${field.name} must not be blank", en.isNotBlank())
            assertTrue("TurkishStrings.${field.name} must not be blank", tr.isNotBlank())
            assertFalse("EnglishStrings.${field.name} must not contain em dash", en.contains('\u2014'))
            assertFalse("TurkishStrings.${field.name} must not contain em dash", tr.contains('\u2014'))
        }
    }

    @Test
    fun localizedFormattingHelpersProduceExpectedEnglishAndTurkishStrings() {
        assertEquals("Mode, DNS, Bypass, Apps", EnglishStrings.localizeChangeSummary("Mode, DNS, Bypass, Apps"))
        assertEquals("Mod, DNS, İstisna, Uygulamalar", TurkishStrings.localizeChangeSummary("Mode, DNS, Bypass, Apps"))

        assertEquals(
            "Reconnect to apply \u00B7 Mode, DNS",
            EnglishStrings.reconnectToApplyWithSummary("Mode, DNS"),
        )
        assertEquals(
            "Yeniden bağlanın \u00B7 Mod, DNS",
            TurkishStrings.reconnectToApplyWithSummary("Mode, DNS"),
        )

        assertEquals("Kombo", formatStageLabel("ComboMultiRecord", TurkishStrings))
        assertEquals("Aşama 2 \u00B7 OOB SNI", formatStageShort(2, "OobSniDesync", TurkishStrings))
        assertEquals("Aşama 3", TurkishStrings.tileStage(3))
        assertEquals(
            "Aşama 1 \u00B7 \u2193 1.5 KB  \u2191 512 B",
            TurkishStrings.notificationConnectedSubtitle(1, "1.5 KB", "512 B"),
        )

        assertEquals("All 4 checks passed", EnglishStrings.diagnosticsAllPassed(4))
        assertEquals("4 kontrolün tamamı geçti", TurkishStrings.diagnosticsAllPassed(4))
        assertEquals("2 of 4 passed", EnglishStrings.diagnosticsPartialPassed(2, 4))
        assertEquals("4 kontrolden 2 geçti", TurkishStrings.diagnosticsPartialPassed(2, 4))
        assertEquals(
            "1 issue detected - check DNS or network settings",
            EnglishStrings.diagnosticsIssuesDetected(1),
        )
        assertEquals(
            "2 sorun algılandı - DNS veya ağ ayarlarını kontrol edin",
            TurkishStrings.diagnosticsIssuesDetected(2),
        )

        assertEquals("Cleared 1 selected app", EnglishStrings.clearedSelectedApps(1))
        assertEquals("Cleared 3 selected apps", EnglishStrings.clearedSelectedApps(3))
        assertEquals("3 seçili uygulama temizlendi", TurkishStrings.clearedSelectedApps(3))

        assertEquals("Kombo", TurkishStrings.desyncModeLabel(DesyncMode.COMBO))
        assertEquals("Sistem", TurkishStrings.languageOptionLabel(AppLanguage.SYSTEM))
        assertEquals("English", TurkishStrings.languageOptionLabel(AppLanguage.EN))
        assertEquals("Türkçe", TurkishStrings.languageOptionLabel(AppLanguage.TR))
        assertEquals("Türkçe", EnglishStrings.languageOptionLabel(AppLanguage.TR))

        val splitSettings = VdpiSettings(
            splitTunnelMode = SplitTunnelMode.ONLY_SELECTED,
            splitPackages = setOf("com.example.one", "com.example.two"),
        )
        assertEquals("2 Routed", splitSummary(splitSettings, EnglishStrings))
        assertEquals("2 Tünelde", splitSummary(splitSettings, TurkishStrings))

        assertEquals("Bölme", TurkishStrings.desyncModeLabel(DesyncMode.SPLIT))
        assertEquals("İnce Parçalama", formatStageLabel("FineFragment", TurkishStrings))
        assertEquals("Doğrudan Geçiş", formatStageLabel("DirectPassthrough", TurkishStrings))
        assertEquals("Yedekle ve Geri Yükle", TurkishStrings.sectionBackupRestore)
    }

    @Test
    fun importErrorReasonLocalizesAllSettingsImportExceptionsInEnglishAndTurkish() {
        val cases: List<Triple<SettingsImportException, String, String>> = listOf(
            Triple(
                SettingsImportException.Empty(),
                "Settings JSON is empty",
                "Ayar JSON dosyası boş",
            ),
            Triple(
                SettingsImportException.TooLarge(),
                "Settings JSON exceeds maximum size",
                "Ayar JSON dosyası en büyük boyutu aşıyor",
            ),
            Triple(
                SettingsImportException.InvalidJson(),
                "Invalid settings JSON",
                "Geçersiz ayar JSON dosyası",
            ),
            Triple(
                SettingsImportException.UnrecognizedFormat(),
                "Unrecognized settings backup format",
                "Tanınmayan ayar yedeği biçimi",
            ),
            Triple(
                SettingsImportException.UnsupportedSchema(version = null),
                "Invalid backup schema version",
                "Geçersiz yedek şema sürümü",
            ),
            Triple(
                SettingsImportException.UnsupportedSchema(version = 99),
                "Unsupported backup schema version: 99",
                "Desteklenmeyen yedek şema sürümü: 99",
            ),
            Triple(
                SettingsImportException.InvalidDesyncMode("bogus"),
                "Unsupported desync mode: bogus",
                "Desteklenmeyen desync modu: bogus",
            ),
            Triple(
                SettingsImportException.InvalidDns("https://dns.example/<redacted>"),
                "Invalid DNS address: https://dns.example/<redacted>",
                "Geçersiz DNS adresi: https://dns.example/<redacted>",
            ),
            Triple(
                SettingsImportException.InvalidSplitMode("weird"),
                "Unsupported split tunnel mode: weird",
                "Desteklenmeyen bölünmüş tünel modu: weird",
            ),
            Triple(
                SettingsImportException.InvalidTheme("neon"),
                "Unsupported theme preference: neon",
                "Desteklenmeyen tema tercihi: neon",
            ),
            Triple(
                SettingsImportException.InvalidLanguage("fr"),
                "Unsupported language preference: fr",
                "Desteklenmeyen dil tercihi: fr",
            ),
        )

        for ((error, expectedEn, expectedTr) in cases) {
            assertEquals(expectedEn, EnglishStrings.importErrorReason(error))
            assertEquals(expectedTr, TurkishStrings.importErrorReason(error))
        }

        val parsedInvalidDns = SettingsRepository.parseSettingsJson(
            """{"desync_mode":"combo","dns_addr":"https://dns.example:99999/secret-token"}""",
        )
        assertTrue(parsedInvalidDns.isFailure)
        val dnsError = parsedInvalidDns.exceptionOrNull() as SettingsImportException.InvalidDns
        assertEquals(
            "Invalid DNS address: https://dns.example/<redacted>",
            EnglishStrings.importErrorReason(dnsError),
        )
        assertEquals(
            "Geçersiz DNS adresi: https://dns.example/<redacted>",
            TurkishStrings.importErrorReason(dnsError),
        )
        assertFalse(TurkishStrings.importErrorReason(dnsError).contains("secret-token"))
    }

    @Test
    fun doctorCheckNameMapsKnownChecksInTurkishAndPassesThroughUnknown() {
        assertEquals("Engine Init", EnglishStrings.doctorCheckName("Engine Init"))
        assertEquals("DNS Ring", EnglishStrings.doctorCheckName("DNS Ring"))
        assertEquals("Native Library", EnglishStrings.doctorCheckName("Native Library"))
        assertEquals("DoH", EnglishStrings.doctorCheckName("DoH"))
        assertEquals("Custom Probe", EnglishStrings.doctorCheckName("Custom Probe"))

        assertEquals("Motor Başlatma", TurkishStrings.doctorCheckName("Engine Init"))
        assertEquals("DNS Halkası", TurkishStrings.doctorCheckName("DNS Ring"))
        assertEquals("Yerel Kütüphane", TurkishStrings.doctorCheckName("Native Library"))
        assertEquals("DoH", TurkishStrings.doctorCheckName("DoH"))
        assertEquals("Custom Probe", TurkishStrings.doctorCheckName("Custom Probe"))
    }

    @Test
    fun buildDiagnosticsReportInTurkishLocalizesHeadersAndChecksWithoutEnglishLeaks() {
        val settings = VdpiSettings(
            desyncMode = DesyncMode.SPLIT,
            chunkSize = 12,
            dnsAddr = "https://dns.custom.example/secret-token-123",
            enableDoh = true,
            ipv4Only = true,
            blockQuic = true,
            bypassDomains = listOf("private-bank.example", "secret.internal.org"),
            splitTunnelMode = SplitTunnelMode.BYPASS_SELECTED,
            splitPackages = setOf("com.secret.wallet"),
            language = AppLanguage.TR,
        )
        val runtime = TunnelRuntimeSnapshot(
            phase = TunnelPhase.CONNECTED,
            telemetry = TelemetrySnapshot(
                running = true,
                uptimeSecs = 95,
                stageNumber = 4,
                stageLabel = "FineFragment",
                dnsAddr = settings.dnsAddr,
                dohEnabled = settings.enableDoh,
            ),
        )
        val report = DoctorReport(
            ok = false,
            checks = listOf(
                DoctorCheck(
                    name = "Engine Init",
                    target = "native",
                    passed = true,
                    latencyMs = 5L,
                    detail = "ok",
                ),
                DoctorCheck(
                    name = "DNS Ring",
                    target = "1.1.1.1",
                    passed = true,
                    latencyMs = 19L,
                    detail = "UDP/DoH OK",
                ),
                DoctorCheck(
                    name = "Native Library",
                    target = "libvdpi_android.so",
                    passed = false,
                    latencyMs = 0L,
                    detail = "missing",
                ),
                DoctorCheck(
                    name = "DoH",
                    target = "https://dns.custom.example/secret-token-123",
                    passed = true,
                    latencyMs = 28L,
                    detail = "HTTP/2 OK",
                ),
            ),
        )

        val text = buildDiagnosticsReport(
            appVersion = "0.6.1",
            engineVersion = "0.6.1",
            settings = settings,
            runtime = runtime,
            doctorReport = report,
            androidRelease = "15",
            androidSdk = 35,
            strings = TurkishStrings,
        )

        assertTrue(text.contains("vdpi Android Tanılama Raporu"))
        assertTrue(text.contains("Uygulama Sürümü: v0.6.1 (Motor: v0.6.1)"))
        assertTrue(text.contains("Tünel Durumu: Bağlı"))
        assertTrue(text.contains("Etkin Aşama: Aşama 4 (İnce Parçalama)"))
        assertTrue(text.contains("Desync Modu: Bölme (split), parça=12"))
        assertTrue(text.contains("DNS: https://dns.custom.example/<redacted> (DoH: etkin, Yalnızca IPv4: evet)"))
        assertTrue(text.contains("QUIC Engelleme: etkin"))
        assertTrue(text.contains("İstisna Alan Adları: 2 yapılandırıldı (gizlendi)"))
        assertTrue(text.contains("Bölünmüş Tünel: Seçilileri Atla (1 uygulama, gizlendi)"))
        assertTrue(text.contains("Tanılama Testleri: BAŞARISIZ (4 kontrol)"))
        assertTrue(text.contains("- [BAŞARILI] Motor Başlatma (native): 5 ms - ok"))
        assertTrue(text.contains("- [BAŞARILI] DNS Halkası (1.1.1.1): 19 ms - UDP/DoH OK"))
        assertTrue(text.contains("- [BAŞARISIZ] Yerel Kütüphane (libvdpi_android.so): 0 ms - missing"))
        assertTrue(text.contains("- [BAŞARILI] DoH (https://dns.custom.example/<redacted>): 28 ms - HTTP/2 OK"))

        assertFalse(text.contains("Engine Init"))
        assertFalse(text.contains("DNS Ring"))
        assertFalse(text.contains("Native Library"))
        assertFalse(text.contains("vdpi Android Diagnostics Report"))
        assertFalse(text.contains("Diagnostic Probes"))
        assertFalse(text.contains("secret-token-123"))
        assertFalse(text.contains('\u2014'))
    }
}
