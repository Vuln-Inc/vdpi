package com.vulninc.vdpi

import com.vulninc.vdpi.data.AppLanguage
import com.vulninc.vdpi.data.SettingsRepository
import com.vulninc.vdpi.data.SplitTunnelMode
import com.vulninc.vdpi.data.ThemePreference
import com.vulninc.vdpi.data.VdpiSettings
import com.vulninc.vdpi.engine.DesyncMode
import com.vulninc.vdpi.ui.computeSettingsChangeSummary
import com.vulninc.vdpi.ui.i18n.EnglishStrings
import com.vulninc.vdpi.ui.i18n.TurkishStrings
import com.vulninc.vdpi.ui.i18n.VdpiStrings
import com.vulninc.vdpi.ui.screens.splitSummary
import com.vulninc.vdpi.util.formatStageLabel
import com.vulninc.vdpi.util.formatStageShort
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
    }
}
