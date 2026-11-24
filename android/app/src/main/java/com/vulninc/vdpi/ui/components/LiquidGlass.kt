package com.vulninc.vdpi.ui.components

import android.graphics.RenderEffect as AndroidRenderEffect
import android.graphics.Shader
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RenderEffect
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.asComposeRenderEffect
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.layer.GraphicsLayer
import androidx.compose.ui.graphics.layer.drawLayer
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.rememberGraphicsLayer
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.layout.boundsInRoot
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens
import kotlin.math.roundToInt

val LocalBottomChromePadding = compositionLocalOf { 100.dp }
val LocalTopOverlayPadding = compositionLocalOf { 0.dp }
val LocalGlassBackdropLayer = compositionLocalOf<GraphicsLayer?> { null }
val LocalReduceTransparency = compositionLocalOf { false }
val LocalIncreaseContrast = compositionLocalOf { false }
val LocalReduceMotion = compositionLocalOf { false }

object VdpiMotion {
    val tabLensSpring = spring<Dp>(dampingRatio = 0.78f, stiffness = 360f)
    val pressSpring = spring<Float>(dampingRatio = 0.85f, stiffness = 800f)
    val toggleSpring = spring<Float>(dampingRatio = 0.78f, stiffness = 620f)
    val popupSpring = spring<IntOffset>(dampingRatio = 0.82f, stiffness = 340f)
}

@RequiresApi(Build.VERSION_CODES.S)
private fun createBackdropBlurEffect(radiusPx: Float): RenderEffect =
    AndroidRenderEffect
        .createBlurEffect(radiusPx, radiusPx, Shader.TileMode.CLAMP)
        .asComposeRenderEffect()

fun Modifier.springPress(
    interactionSource: MutableInteractionSource,
    pressedScale: Float = 0.97f,
): Modifier = composed {
    if (LocalReduceMotion.current) return@composed this
    val isPressed by interactionSource.collectIsPressedAsState()
    val scale by animateFloatAsState(
        targetValue = if (isPressed) pressedScale else 1f,
        animationSpec = VdpiMotion.pressSpring,
        label = "springPressScale",
    )
    this.graphicsLayer {
        scaleX = scale
        scaleY = scale
    }
}

/**
 * Liquid Glass material strictly for the floating functional chrome layer:
 * floating tab bar, floating live-tunnel accessory pill, top reconnect banner,
 * floating circular toolbar buttons, and floating snackbars.
 *
 * Never apply to content cards, backgrounds, or list rows.
 */
fun Modifier.liquidGlass(
    shape: Shape = CircleShape,
    elevated: Boolean = true,
    rimTint: Color? = null,
    fillTint: Color? = null,
): Modifier = composed {
    val palette = VdpiThemeTokens.palette
    val reduceTransparency = LocalReduceTransparency.current
    val increaseContrast = LocalIncreaseContrast.current

    if (reduceTransparency) {
        val solidFill = if (palette.isDark) Color(0xEB1C1C1E) else Color(0xF2FFFFFF)
        val borderColor = if (increaseContrast) palette.borderStrong else palette.border
        return@composed this
            .clip(shape)
            .background(solidFill)
            .border(width = 1.dp, color = borderColor, shape = shape)
    }

    val backdropLayer = LocalGlassBackdropLayer.current
    val density = LocalDensity.current
    val useRealBlur = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && backdropLayer != null
    val blurLayer = if (useRealBlur) rememberGraphicsLayer() else null
    val blurRadiusPx = remember(density) {
        with(density) { 16.dp.toPx() }
    }
    val cachedBlurEffect = remember(useRealBlur, blurRadiusPx) {
        if (useRealBlur && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            runCatching { createBackdropBlurEffect(blurRadiusPx) }.getOrNull()
        } else {
            null
        }
    }
    var boundsInRoot by remember { mutableStateOf(Rect.Zero) }

    val rawFill = fillTint ?: if (elevated) palette.glassFillElevated else palette.glassFill
    val baseFill = if (useRealBlur || fillTint != null) {
        rawFill
    } else {
        rawFill.copy(alpha = (rawFill.alpha + 0.16f).coerceAtMost(0.92f))
    }
    val topFill = baseFill.copy(
        alpha = (baseFill.alpha * if (palette.isDark) 1.03f else 1.04f).coerceAtMost(0.95f),
    )
    val bottomFill = baseFill.copy(
        alpha = (baseFill.alpha * if (palette.isDark) 0.90f else 0.94f).coerceAtLeast(0.08f),
    )
    val bodyBrush = remember(topFill, bottomFill) {
        Brush.verticalGradient(colors = listOf(topFill, bottomFill))
    }

    // Subtle top specular + gentle bottom inner light bounce without clouding dark-mode active pill.
    val sheenTopAlpha = if (palette.isDark) 0.045f else 0.24f
    val sheenBottomAlpha = if (palette.isDark) 0.025f else 0.12f
    val sheenBrush = remember(sheenTopAlpha, sheenBottomAlpha) {
        Brush.verticalGradient(
            0.00f to Color.White.copy(alpha = sheenTopAlpha),
            0.26f to Color.Transparent,
            0.78f to Color.Transparent,
            1.00f to Color.White.copy(alpha = sheenBottomAlpha),
        )
    }

    val rimTop = if (rimTint != null) {
        lerp(
            palette.glassRimTop,
            rimTint.copy(alpha = if (palette.isDark) 0.44f else 0.42f),
            0.38f,
        )
    } else {
        palette.glassRimTop
    }
    val rimSide = if (rimTint != null) {
        lerp(
            palette.glassRimSide,
            rimTint.copy(alpha = if (palette.isDark) 0.16f else 0.20f),
            0.35f,
        )
    } else {
        palette.glassRimSide
    }
    val rimBottom = if (rimTint != null) {
        lerp(
            palette.glassRimBottom,
            rimTint.copy(alpha = if (palette.isDark) 0.24f else 0.28f),
            0.35f,
        )
    } else {
        palette.glassRimBottom
    }

    // Apple iOS 26 Liquid Glass catchlight rim: bright top specular, refractive middle, bottom bounce.
    val rimBrush = remember(rimTop, rimSide, rimBottom) {
        Brush.verticalGradient(
            0.00f to rimTop,
            0.38f to rimSide,
            0.74f to rimSide,
            1.00f to rimBottom,
        )
    }

    val neutralShadow = remember(palette.isDark) {
        Color.Black.copy(alpha = if (palette.isDark) 0.56f else 0.16f)
    }

    val shadowModifier = if (elevated) {
        Modifier.shadow(
            elevation = if (palette.isDark) 14.dp else 10.dp,
            shape = shape,
            clip = false,
            ambientColor = neutralShadow,
            spotColor = neutralShadow,
        )
    } else {
        Modifier
    }

    val positionModifier = if (useRealBlur) {
        Modifier.onGloballyPositioned { coords ->
            if (coords.isAttached) {
                boundsInRoot = coords.boundsInRoot()
            }
        }
    } else {
        Modifier
    }

    val borderModifier = if (increaseContrast) {
        Modifier.border(width = 1.dp, color = palette.borderStrong, shape = shape)
    } else {
        Modifier.border(width = 0.5.dp, brush = rimBrush, shape = shape)
    }

    this
        .then(shadowModifier)
        .then(positionModifier)
        .clip(shape)
        .drawBehind {
            if (backdropLayer != null &&
                blurLayer != null &&
                cachedBlurEffect != null &&
                backdropLayer.size.width > 0 &&
                backdropLayer.size.height > 0 &&
                size.width >= 32f &&
                size.height >= 32f &&
                !boundsInRoot.isEmpty
            ) {
                runCatching {
                    val targetSize = IntSize(
                        width = size.width.roundToInt().coerceAtLeast(1),
                        height = size.height.roundToInt().coerceAtLeast(1),
                    )
                    blurLayer.renderEffect = cachedBlurEffect
                    blurLayer.record(size = targetSize) {
                        translate(left = -boundsInRoot.left, top = -boundsInRoot.top) {
                            drawLayer(backdropLayer)
                        }
                    }
                    drawLayer(blurLayer)
                }
            }

            drawRect(brush = bodyBrush)

            if (size.height > 0f) {
                drawRect(brush = sheenBrush)
            }
        }
        .then(borderModifier)
}

@Composable
fun FloatingGlassIconButton(
    onClick: () -> Unit,
    contentDescription: String,
    modifier: Modifier = Modifier,
    size: Dp = 42.dp,
    badgeColor: Color? = null,
    enabled: Boolean = true,
    icon: @Composable BoxScope.() -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val interactionSource = remember { MutableInteractionSource() }
    val touchTarget = if (size >= 44.dp) size else 44.dp

    Box(
        modifier = modifier
            .size(touchTarget)
            .alpha(if (enabled) 1f else 0.42f)
            .semantics {
                this.contentDescription = contentDescription
                this.role = Role.Button
            }
            .clickable(
                interactionSource = interactionSource,
                indication = null,
                enabled = enabled,
                role = Role.Button,
            ) {
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                onClick()
            },
        contentAlignment = Alignment.Center,
    ) {
        Box(
            modifier = Modifier
                .size(size)
                .springPress(interactionSource = interactionSource, pressedScale = 0.96f),
            contentAlignment = Alignment.Center,
        ) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .liquidGlass(
                        shape = CircleShape,
                        elevated = true,
                    ),
                contentAlignment = Alignment.Center,
                content = icon,
            )

            if (badgeColor != null) {
                Box(
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(top = 4.dp, end = 4.dp)
                        .size(7.dp)
                        .clip(CircleShape)
                        .background(badgeColor)
                        .border(
                            width = 1.dp,
                            color = palette.canvas,
                            shape = CircleShape,
                        ),
                )
            }
        }
    }
}

/**
 * Apple HIG Scroll Edge Effect: dissolves scrolled content cleanly into the canvas edge
 * behind the floating tab bar / 3-button nav bar (bottom) or status bar (top).
 */
@Composable
fun ScrollEdgeFadeScrim(
    modifier: Modifier = Modifier,
    height: Dp = 96.dp,
    fromBottom: Boolean = true,
) {
    if (height <= 0.dp) return
    val canvas = VdpiThemeTokens.palette.canvas
    val brush = remember(canvas, fromBottom) {
        if (fromBottom) {
            Brush.verticalGradient(
                0.00f to canvas.copy(alpha = 0.000f),
                0.18f to canvas.copy(alpha = 0.280f),
                0.36f to canvas.copy(alpha = 0.680f),
                0.54f to canvas.copy(alpha = 0.880f),
                0.72f to canvas.copy(alpha = 0.960f),
                0.88f to canvas.copy(alpha = 0.995f),
                1.00f to canvas,
            )
        } else {
            Brush.verticalGradient(
                0.00f to canvas,
                0.12f to canvas.copy(alpha = 0.995f),
                0.28f to canvas.copy(alpha = 0.960f),
                0.46f to canvas.copy(alpha = 0.880f),
                0.64f to canvas.copy(alpha = 0.680f),
                0.82f to canvas.copy(alpha = 0.280f),
                1.00f to canvas.copy(alpha = 0.000f),
            )
        }
    }

    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(height)
            .background(brush),
    )
}

/**
 * Opaque Apple Inset Grouped surface for the content layer.
 * Zero blur and zero drop shadow; adds a crisp 1dp border when Increase Contrast is enabled.
 */
@Composable
fun InsetGroupedCard(
    modifier: Modifier = Modifier,
    radius: Dp = 16.dp,
    backgroundColor: Color = VdpiThemeTokens.palette.surface,
    content: @Composable ColumnScope.() -> Unit,
) {
    val increaseContrast = LocalIncreaseContrast.current
    val shape = remember(radius) { RoundedCornerShape(radius) }
    val contrastBorder = if (increaseContrast) {
        Modifier.border(
            width = 1.dp,
            color = VdpiThemeTokens.palette.borderStrong,
            shape = shape,
        )
    } else {
        Modifier
    }
    Column(
        modifier = modifier
            .clip(shape)
            .background(backgroundColor)
            .then(contrastBorder),
        content = content,
    )
}
