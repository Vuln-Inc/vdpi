package com.vulninc.vdpi.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.vulninc.vdpi.R
import com.vulninc.vdpi.data.ThemePreference

val GeistSans = FontFamily(
    Font(R.font.geist_regular, FontWeight.Normal),
    Font(R.font.geist_medium, FontWeight.Medium),
    Font(R.font.geist_semibold, FontWeight.SemiBold),
)

val GeistMono = FontFamily(
    Font(R.font.geist_mono_regular, FontWeight.Normal),
    Font(R.font.geist_mono_medium, FontWeight.Medium),
)

@Immutable
data class VdpiPalette(
    val isDark: Boolean,
    val canvas: Color,
    val surface: Color,
    val surfaceRaised: Color,
    val border: Color,
    val borderStrong: Color,
    val inkPrimary: Color,
    val inkSecondary: Color,
    val inkMuted: Color,
    val primaryButtonBg: Color,
    val primaryButtonInk: Color,
    val signal: Color,
    val signalTint: Color,
    val warning: Color,
    val warningTint: Color,
    val danger: Color,
    val dangerTint: Color,
    val accent: Color = Color(0xFF409CFF),
    val glassFill: Color = Color(0x9E1C1C1E),
    val glassFillElevated: Color = Color(0xA81C1C1E),
    val glassRimTop: Color = Color(0x57FFFFFF),
    val glassRimSide: Color = Color(0x14FFFFFF),
    val glassRimBottom: Color = Color(0x24FFFFFF),
    val signalThumbInk: Color = Color(0xFFFFFFFF),
)

// Apple iOS Dark grouped hierarchy (OLED canvas + elevated grouped cards)
val DarkVdpiPalette = VdpiPalette(
    isDark = true,
    canvas = Color(0xFF000000),
    surface = Color(0xFF1C1C1E),
    surfaceRaised = Color(0xFF2C2C2E),
    border = Color(0xFF38383A),
    borderStrong = Color(0xFF48484A),
    inkPrimary = Color(0xFFFFFFFF),
    inkSecondary = Color(0xFF98989F),
    inkMuted = Color(0xFF8E8E93),
    primaryButtonBg = Color(0xFF0066CC),
    primaryButtonInk = Color(0xFFFFFFFF),
    signal = Color(0xFF30D158),
    signalTint = Color(0x1F30D158),
    warning = Color(0xFFFF9F0A),
    warningTint = Color(0x24FF9F0A),
    danger = Color(0xFFFF453A),
    dangerTint = Color(0x24FF453A),
    accent = Color(0xFF409CFF),
    glassFill = Color(0x9E1C1C1E),
    glassFillElevated = Color(0xA81C1C1E),
    glassRimTop = Color(0x57FFFFFF),
    glassRimSide = Color(0x14FFFFFF),
    glassRimBottom = Color(0x24FFFFFF),
    signalThumbInk = Color(0xFFFFFFFF),
)

// Apple iOS Light grouped hierarchy (systemGroupedBackground + white cards)
val LightVdpiPalette = VdpiPalette(
    isDark = false,
    canvas = Color(0xFFF2F2F7),
    surface = Color(0xFFFFFFFF),
    surfaceRaised = Color(0xFFE5E5EA),
    border = Color(0xFFC6C6C8),
    borderStrong = Color(0xFFAEAEB2),
    inkPrimary = Color(0xFF000000),
    inkSecondary = Color(0xFF5C5C60),
    inkMuted = Color(0xFF6C6C70),
    primaryButtonBg = Color(0xFF0066CC),
    primaryButtonInk = Color(0xFFFFFFFF),
    signal = Color(0xFF1E7E34),
    signalTint = Color(0x1434C759),
    warning = Color(0xFFC93400),
    warningTint = Color(0x18FF9500),
    danger = Color(0xFFD70015),
    dangerTint = Color(0x14FF3B30),
    accent = Color(0xFF0066CC),
    glassFill = Color(0xB3FFFFFF),
    glassFillElevated = Color(0xBDFFFFFF),
    glassRimTop = Color(0xEBFFFFFF),
    glassRimSide = Color(0x59FFFFFF),
    glassRimBottom = Color(0x8CFFFFFF),
    signalThumbInk = Color(0xFFFFFFFF),
)

object VdpiTextStyles {
    val pageTitle = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 34.sp,
        lineHeight = 40.sp,
        letterSpacing = (-0.45).sp,
    )
    val hero = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 26.sp,
        lineHeight = 32.sp,
        letterSpacing = (-0.35).sp,
    )
    val screenTitle = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp,
        lineHeight = 25.sp,
        letterSpacing = (-0.25).sp,
    )
    val sheetTitle = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 17.sp,
        lineHeight = 22.sp,
        letterSpacing = (-0.2).sp,
    )
    val rowTitle = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 21.sp,
        letterSpacing = (-0.15).sp,
    )
    val body = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.Normal,
        fontSize = 15.sp,
        lineHeight = 20.sp,
        letterSpacing = (-0.1).sp,
    )
    val caption = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.Normal,
        fontSize = 13.sp,
        lineHeight = 18.sp,
        letterSpacing = 0.sp,
    )
    val button = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp,
        lineHeight = 21.sp,
        letterSpacing = (-0.15).sp,
    )
    val overline = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.Medium,
        fontSize = 13.sp,
        lineHeight = 18.sp,
        letterSpacing = 0.1.sp,
    )
    val monoMetric = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.Normal,
        fontSize = 15.sp,
        lineHeight = 20.sp,
        fontFeatureSettings = "tnum",
    )
    val monoSmall = TextStyle(
        fontFamily = GeistMono,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 16.sp,
        fontFeatureSettings = "tnum",
    )
    val tabLabel = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        lineHeight = 13.sp,
        letterSpacing = 0.1.sp,
    )
}

val LocalVdpiPalette = staticCompositionLocalOf { DarkVdpiPalette }

val VdpiTypography = Typography(
    displaySmall = VdpiTextStyles.pageTitle,
    headlineSmall = VdpiTextStyles.screenTitle,
    titleMedium = VdpiTextStyles.sheetTitle,
    bodyLarge = VdpiTextStyles.rowTitle,
    bodyMedium = VdpiTextStyles.body,
    bodySmall = VdpiTextStyles.caption,
    labelLarge = VdpiTextStyles.button,
    labelMedium = VdpiTextStyles.overline,
    labelSmall = VdpiTextStyles.monoSmall,
)

@Composable
fun VdpiTheme(
    preference: ThemePreference,
    content: @Composable () -> Unit,
) {
    val useDark = when (preference) {
        ThemePreference.DARK -> true
        ThemePreference.LIGHT -> false
        ThemePreference.SYSTEM -> isSystemInDarkTheme()
    }
    val palette = if (useDark) DarkVdpiPalette else LightVdpiPalette
    val materialColors = if (useDark) {
        darkColorScheme(
            primary = palette.accent,
            onPrimary = palette.primaryButtonInk,
            secondary = palette.signal,
            onSecondary = palette.signalThumbInk,
            background = palette.canvas,
            onBackground = palette.inkPrimary,
            surface = palette.surface,
            onSurface = palette.inkPrimary,
            surfaceVariant = palette.surfaceRaised,
            onSurfaceVariant = palette.inkSecondary,
            outline = palette.border,
            outlineVariant = palette.borderStrong,
            error = palette.danger,
            onError = palette.primaryButtonInk,
        )
    } else {
        lightColorScheme(
            primary = palette.accent,
            onPrimary = palette.primaryButtonInk,
            secondary = palette.signal,
            onSecondary = palette.signalThumbInk,
            background = palette.canvas,
            onBackground = palette.inkPrimary,
            surface = palette.surface,
            onSurface = palette.inkPrimary,
            surfaceVariant = palette.surfaceRaised,
            onSurfaceVariant = palette.inkSecondary,
            outline = palette.border,
            outlineVariant = palette.borderStrong,
            error = palette.danger,
            onError = palette.primaryButtonInk,
        )
    }

    CompositionLocalProvider(LocalVdpiPalette provides palette) {
        MaterialTheme(
            colorScheme = materialColors,
            typography = VdpiTypography,
            content = content,
        )
    }
}

object VdpiThemeTokens {
    val palette: VdpiPalette
        @Composable get() = LocalVdpiPalette.current
}
