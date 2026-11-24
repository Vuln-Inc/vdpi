package com.vulninc.vdpi.ui.components

import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens

/**
 * Draws a 0.5dp vertical gradient hairline border around dark-mode
 * [InsetGroupedCard] surfaces. No-ops in light theme and yields to the
 * 1dp high-contrast border when Increase Contrast is enabled.
 */
fun Modifier.sculptedDarkCardBorder(
    radius: Dp = 16.dp,
): Modifier = composed {
    val palette = VdpiThemeTokens.palette
    val increaseContrast = LocalIncreaseContrast.current
    if (!palette.isDark || increaseContrast) {
        return@composed this
    }
    val specularBrush = remember {
        Brush.verticalGradient(
            colors = listOf(
                Color.White.copy(alpha = 0.09f),
                Color.White.copy(alpha = 0.02f),
            ),
        )
    }
    this.drawWithContent {
        drawContent()
        val strokePx = 0.5.dp.toPx()
        val half = strokePx * 0.5f
        val cornerPx = (radius.toPx() - half).coerceAtLeast(0f)
        drawRoundRect(
            brush = specularBrush,
            topLeft = Offset(half, half),
            size = Size(
                width = (size.width - strokePx).coerceAtLeast(0f),
                height = (size.height - strokePx).coerceAtLeast(0f),
            ),
            cornerRadius = CornerRadius(cornerPx, cornerPx),
            style = Stroke(width = strokePx),
        )
    }
}
