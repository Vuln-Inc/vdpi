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
    val topHighlight: Color,
    val inkPrimary: Color,
    val inkSecondary: Color,
    val inkMuted: Color,
    val primaryButtonBg: Color,
    val primaryButtonInk: Color,
    val signal: Color,
    val signalTint: Color,
    val signalBorder: Color,
    val warning: Color,
    val warningTint: Color,
    val danger: Color,
    val dangerTint: Color,
    val accent: Color = Color(0xFF19C8FF),
    val accentTint: Color = Color(0x1F19C8FF),
    val glassFill: Color = Color(0xB3161922),
    val glassFillElevated: Color = Color(0xCC1C202B),
    val glassFillSubtle: Color = Color(0x7A141720),
    val glassLensFill: Color = Color(0x33FFFFFF),
    val glassRimTop: Color = Color(0x59FFFFFF),
    val glassRimSide: Color = Color(0x1CFFFFFF),
    val glassRimBottom: Color = Color(0x2EFFFFFF),
    val glassSheenTop: Color = Color(0x1AFFFFFF),
    val glassShadow: Color = Color(0xB3000000),
    val signalGlow: Color = Color(0x4D10E896),
    val warningGlow: Color = Color(0x47F59E0B),
    val dangerGlow: Color = Color(0x4DFF4D6D),
    val signalThumbInk: Color = Color(0xFF03140C),
)

val DarkVdpiPalette = VdpiPalette(
    isDark = true,
    canvas = Color(0xFF000000),
    surface = Color(0xFF0D0E12),
    surfaceRaised = Color(0xFF181A20),
    border = Color(0x24FFFFFF),
    borderStrong = Color(0x3DFFFFFF),
    topHighlight = Color(0x1FFFFFFF),
    inkPrimary = Color(0xFFFFFFFF),
    inkSecondary = Color(0xFFA1A8B3),
    inkMuted = Color(0xFF7C8594),
    primaryButtonBg = Color(0xFFFFFFFF),
    primaryButtonInk = Color(0xFF06080B),
    signal = Color(0xFF10E896),
    signalTint = Color(0x1F10E896),
    signalBorder = Color(0x5910E896),
    warning = Color(0xFFF59E0B),
    warningTint = Color(0x1FF59E0B),
    danger = Color(0xFFFF4D6D),
    dangerTint = Color(0x21FF4D6D),
    accent = Color(0xFF19C8FF),
    accentTint = Color(0x1F19C8FF),
    glassFill = Color(0xB3161922),
    glassFillElevated = Color(0xCC1C202B),
    glassFillSubtle = Color(0x7A141720),
    glassLensFill = Color(0x33FFFFFF),
    glassRimTop = Color(0x59FFFFFF),
    glassRimSide = Color(0x1CFFFFFF),
    glassRimBottom = Color(0x2EFFFFFF),
    glassSheenTop = Color(0x1AFFFFFF),
    glassShadow = Color(0xB3000000),
    signalGlow = Color(0x4D10E896),
    warningGlow = Color(0x47F59E0B),
    dangerGlow = Color(0x4DFF4D6D),
    signalThumbInk = Color(0xFF03140C),
)

val LightVdpiPalette = VdpiPalette(
    isDark = false,
    canvas = Color(0xFFF4F7FA),
    surface = Color(0xFFFFFFFF),
    surfaceRaised = Color(0xFFEAEFF5),
    border = Color(0x1F0F172A),
    borderStrong = Color(0x380F172A),
    topHighlight = Color(0xB3FFFFFF),
    inkPrimary = Color(0xFF0A0F1A),
    inkSecondary = Color(0xFF4B5565),
    inkMuted = Color(0xFF64748B),
    primaryButtonBg = Color(0xFF0A0F1A),
    primaryButtonInk = Color(0xFFFFFFFF),
    signal = Color(0xFF059669),
    signalTint = Color(0x17059669),
    signalBorder = Color(0x52059669),
    warning = Color(0xFFD97706),
    warningTint = Color(0x1AD97706),
    danger = Color(0xFFE11D48),
    dangerTint = Color(0x17E11D48),
    accent = Color(0xFF0284C7),
    accentTint = Color(0x170284C7),
    glassFill = Color(0xCCFFFFFF),
    glassFillElevated = Color(0xE0FFFFFF),
    glassFillSubtle = Color(0xA6FFFFFF),
    glassLensFill = Color(0xE6FFFFFF),
    glassRimTop = Color(0xF2FFFFFF),
    glassRimSide = Color(0x1A0F172A),
    glassRimBottom = Color(0x260F172A),
    glassSheenTop = Color(0x8CFFFFFF),
    glassShadow = Color(0x240F172A),
    signalGlow = Color(0x3D059669),
    warningGlow = Color(0x38D97706),
    dangerGlow = Color(0x38E11D48),
    signalThumbInk = Color(0xFFFFFFFF),
)

object VdpiTextStyles {
    val pageTitle = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 30.sp,
        lineHeight = 36.sp,
        letterSpacing = (-0.8).sp,
    )
    val hero = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 30.sp,
        lineHeight = 34.sp,
        letterSpacing = (-0.9).sp,
    )
    val heroMetric = TextStyle(
        fontFamily = GeistMono,
        fontWeight = FontWeight.Medium,
        fontSize = 20.sp,
        lineHeight = 24.sp,
        fontFeatureSettings = "tnum",
    )
    val screenTitle = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp,
        lineHeight = 26.sp,
        letterSpacing = (-0.4).sp,
    )
    val sheetTitle = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 18.sp,
        lineHeight = 24.sp,
        letterSpacing = (-0.3).sp,
    )
    val rowTitle = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp,
        lineHeight = 20.sp,
        letterSpacing = (-0.1).sp,
    )
    val body = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.Normal,
        fontSize = 13.sp,
        lineHeight = 19.sp,
    )
    val caption = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 17.sp,
    )
    val button = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp,
        lineHeight = 18.sp,
        letterSpacing = (-0.1).sp,
    )
    val tabLabel = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.Medium,
        fontSize = 10.5.sp,
        lineHeight = 13.sp,
        letterSpacing = 0.15.sp,
    )
    val overline = TextStyle(
        fontFamily = GeistMono,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        lineHeight = 14.sp,
        letterSpacing = 0.85.sp,
        fontFeatureSettings = "tnum",
    )
    val monoMetric = TextStyle(
        fontFamily = GeistMono,
        fontWeight = FontWeight.Medium,
        fontSize = 13.sp,
        lineHeight = 18.sp,
        fontFeatureSettings = "tnum",
    )
    val monoSmall = TextStyle(
        fontFamily = GeistMono,
        fontWeight = FontWeight.Normal,
        fontSize = 11.sp,
        lineHeight = 15.sp,
        fontFeatureSettings = "tnum",
    )
}

val LocalVdpiPalette = staticCompositionLocalOf { DarkVdpiPalette }

val VdpiTypography = Typography(
    displaySmall = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 28.sp,
        lineHeight = 32.sp,
        letterSpacing = (-0.8).sp,
    ),
    headlineSmall = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp,
        lineHeight = 26.sp,
        letterSpacing = (-0.4).sp,
    ),
    titleMedium = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.Medium,
        fontSize = 15.sp,
        lineHeight = 20.sp,
        letterSpacing = (-0.15).sp,
    ),
    bodyMedium = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
    bodySmall = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 17.sp,
    ),
    labelLarge = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp,
        lineHeight = 18.sp,
        letterSpacing = (-0.1).sp,
    ),
    labelMedium = TextStyle(
        fontFamily = GeistMono,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        lineHeight = 14.sp,
        letterSpacing = 0.6.sp,
        fontFeatureSettings = "tnum",
    ),
    labelSmall = TextStyle(
        fontFamily = GeistMono,
        fontWeight = FontWeight.Normal,
        fontSize = 11.sp,
        lineHeight = 15.sp,
        fontFeatureSettings = "tnum",
    ),
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
            primary = palette.inkPrimary,
            onPrimary = palette.canvas,
            background = palette.canvas,
            onBackground = palette.inkPrimary,
            surface = palette.surface,
            onSurface = palette.inkPrimary,
            surfaceVariant = palette.surfaceRaised,
            onSurfaceVariant = palette.inkSecondary,
            outline = palette.border,
            error = palette.danger,
        )
    } else {
        lightColorScheme(
            primary = palette.inkPrimary,
            onPrimary = palette.canvas,
            background = palette.canvas,
            onBackground = palette.inkPrimary,
            surface = palette.surface,
            onSurface = palette.inkPrimary,
            surfaceVariant = palette.surfaceRaised,
            onSurfaceVariant = palette.inkSecondary,
            outline = palette.border,
            error = palette.danger,
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
