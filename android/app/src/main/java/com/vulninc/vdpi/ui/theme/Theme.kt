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
)

val DarkVdpiPalette = VdpiPalette(
    isDark = true,
    canvas = Color(0xFF09090B),
    surface = Color(0xFF111113),
    surfaceRaised = Color(0xFF18181B),
    border = Color(0x1AFFFFFF),
    borderStrong = Color(0x33FFFFFF),
    topHighlight = Color(0x12FFFFFF),
    inkPrimary = Color(0xFFF4F4F5),
    inkSecondary = Color(0xFFA1A1AA),
    inkMuted = Color(0xFF8E8E9A),
    primaryButtonBg = Color(0xFFF4F4F5),
    primaryButtonInk = Color(0xFF09090B),
    signal = Color(0xFF10B981),
    signalTint = Color(0x1A10B981),
    signalBorder = Color(0x5210B981),
    warning = Color(0xFFF59E0B),
    warningTint = Color(0x1AF59E0B),
    danger = Color(0xFFEF4444),
    dangerTint = Color(0x1AEF4444),
)

val LightVdpiPalette = VdpiPalette(
    isDark = false,
    canvas = Color(0xFFFAFAFA),
    surface = Color(0xFFFFFFFF),
    surfaceRaised = Color(0xFFF4F4F5),
    border = Color(0xFFE4E4E7),
    borderStrong = Color(0xFFD4D4D8),
    topHighlight = Color.Transparent,
    inkPrimary = Color(0xFF09090B),
    inkSecondary = Color(0xFF52525B),
    inkMuted = Color(0xFF5C5C66),
    primaryButtonBg = Color(0xFF09090B),
    primaryButtonInk = Color(0xFFFAFAFA),
    signal = Color(0xFF047857),
    signalTint = Color(0x14047857),
    signalBorder = Color(0x4D047857),
    warning = Color(0xFFB45309),
    warningTint = Color(0x18B45309),
    danger = Color(0xFFDC2626),
    dangerTint = Color(0x14DC2626),
)

object VdpiTextStyles {
    val hero = TextStyle(
        fontFamily = GeistSans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 30.sp,
        lineHeight = 34.sp,
        letterSpacing = (-0.9).sp,
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
