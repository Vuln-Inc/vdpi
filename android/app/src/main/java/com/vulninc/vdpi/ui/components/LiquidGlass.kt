package com.vulninc.vdpi.ui.components

import android.graphics.RenderEffect as AndroidRenderEffect
import android.graphics.Shader
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
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
import androidx.compose.ui.geometry.Offset
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
import com.vulninc.vdpi.vpn.TunnelPhase
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.max
import kotlin.math.roundToInt
import kotlin.math.sin

val LocalBottomChromePadding = compositionLocalOf { 104.dp }
val LocalTopOverlayPadding = compositionLocalOf { 0.dp }
val LocalGlassBackdropLayer = compositionLocalOf<GraphicsLayer?> { null }

object VdpiMotion {
    val tabLensSpring = spring<Dp>(dampingRatio = 0.74f, stiffness = 340f)
    val tabLensFloatSpring = spring<Float>(dampingRatio = 0.74f, stiffness = 340f)
    val pressSpring = spring<Float>(dampingRatio = 0.78f, stiffness = 750f)
    val toggleSpring = spring<Float>(dampingRatio = 0.70f, stiffness = 520f)
    val popupSpring = spring<IntOffset>(dampingRatio = 0.76f, stiffness = 280f)
    val miniBarSpring = spring<IntOffset>(dampingRatio = 0.84f, stiffness = 310f)
}

@RequiresApi(Build.VERSION_CODES.S)
private fun createBackdropBlurEffect(radiusPx: Float): RenderEffect =
    AndroidRenderEffect
        .createBlurEffect(radiusPx, radiusPx, Shader.TileMode.CLAMP)
        .asComposeRenderEffect()

fun Modifier.springPress(
    interactionSource: MutableInteractionSource,
    pressedScale: Float = 0.96f,
): Modifier = composed {
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

fun Modifier.liquidGlass(
    shape: Shape = CircleShape,
    elevated: Boolean = true,
    rimTint: Color? = null,
    fillTint: Color? = null,
): Modifier = composed {
    val palette = VdpiThemeTokens.palette
    val backdropLayer = LocalGlassBackdropLayer.current
    val density = LocalDensity.current
    val useRealBlur = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && backdropLayer != null
    val blurLayer = if (useRealBlur) rememberGraphicsLayer() else null
    val blurRadiusPx = remember(elevated, density) {
        with(density) { (if (elevated) 22.dp else 16.dp).toPx() }
    }
    val cachedBlurEffect = remember(useRealBlur, blurRadiusPx) {
        if (useRealBlur && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            runCatching { createBackdropBlurEffect(blurRadiusPx) }.getOrNull()
        } else {
            null
        }
    }
    var boundsInRoot by remember { mutableStateOf(Rect.Zero) }

    val baseFill = fillTint ?: if (elevated) palette.glassFillElevated else palette.glassFill
    val topFill = baseFill.copy(
        alpha = (baseFill.alpha * if (palette.isDark) 1.06f else 1.04f).coerceAtMost(0.96f),
    )
    val bottomFill = baseFill.copy(
        alpha = (baseFill.alpha * if (palette.isDark) 0.90f else 0.94f).coerceAtLeast(0.08f),
    )

    val rimTop = if (rimTint != null) {
        lerp(
            palette.glassRimTop,
            rimTint.copy(alpha = if (palette.isDark) 0.72f else 0.62f),
            0.55f,
        )
    } else {
        palette.glassRimTop
    }
    val rimSide = if (rimTint != null) {
        lerp(
            palette.glassRimSide,
            rimTint.copy(alpha = if (palette.isDark) 0.28f else 0.24f),
            0.50f,
        )
    } else {
        palette.glassRimSide
    }
    val rimBottom = if (rimTint != null) {
        lerp(
            palette.glassRimBottom,
            rimTint.copy(alpha = if (palette.isDark) 0.42f else 0.34f),
            0.50f,
        )
    } else {
        palette.glassRimBottom
    }

    val rimBrush = remember(rimTop, rimSide, rimBottom) {
        Brush.verticalGradient(
            0.00f to rimTop,
            0.36f to rimSide,
            0.78f to rimSide,
            1.00f to rimBottom,
        )
    }

    val shadowModifier = if (elevated) {
        Modifier.shadow(
            elevation = if (palette.isDark) 16.dp else 12.dp,
            shape = shape,
            clip = false,
            ambientColor = palette.glassShadow,
            spotColor = palette.glassShadow,
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
                size.width >= 1f &&
                size.height >= 1f &&
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

            // Layered vertical translucent body tint
            drawRect(
                brush = Brush.verticalGradient(
                    colors = listOf(topFill, bottomFill),
                ),
            )

            // Inner top refraction sheen over the top 38%
            if (size.height > 0f) {
                drawRect(
                    brush = Brush.verticalGradient(
                        colorStops = arrayOf(
                            0.00f to palette.glassSheenTop,
                            0.38f to Color.Transparent,
                        ),
                        startY = 0f,
                        endY = size.height,
                    ),
                )
            }
        }
        .border(width = 1.dp, brush = rimBrush, shape = shape)
}

@Composable
fun LiquidGlassCard(
    modifier: Modifier = Modifier,
    radius: Dp = 24.dp,
    rimTint: Color? = null,
    fillTint: Color? = null,
    elevated: Boolean = true,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier = modifier.liquidGlass(
            shape = RoundedCornerShape(radius),
            elevated = elevated,
            rimTint = rimTint,
            fillTint = fillTint,
        ),
        content = content,
    )
}

@Composable
fun LiquidGlassCapsule(
    modifier: Modifier = Modifier,
    rimTint: Color? = null,
    fillTint: Color? = null,
    elevated: Boolean = true,
    content: @Composable BoxScope.() -> Unit,
) {
    Box(
        modifier = modifier.liquidGlass(
            shape = CircleShape,
            elevated = elevated,
            rimTint = rimTint,
            fillTint = fillTint,
        ),
        contentAlignment = Alignment.Center,
        content = content,
    )
}

@Composable
fun FloatingGlassIconButton(
    onClick: () -> Unit,
    contentDescription: String,
    modifier: Modifier = Modifier,
    size: Dp = 44.dp,
    badgeColor: Color? = null,
    enabled: Boolean = true,
    icon: @Composable BoxScope.() -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val interactionSource = remember { MutableInteractionSource() }

    Box(
        modifier = modifier
            .size(size)
            .alpha(if (enabled) 1f else 0.45f)
            .springPress(interactionSource = interactionSource, pressedScale = 0.92f)
            .semantics {
                this.contentDescription = contentDescription
                this.role = Role.Button
            },
        contentAlignment = Alignment.Center,
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .liquidGlass(
                    shape = CircleShape,
                    elevated = true,
                )
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
            content = icon,
        )

        if (badgeColor != null) {
            Box(
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(top = 5.dp, end = 5.dp)
                    .size(7.dp)
                    .shadow(
                        elevation = 4.dp,
                        shape = CircleShape,
                        clip = false,
                        ambientColor = badgeColor,
                        spotColor = badgeColor,
                    )
                    .clip(CircleShape)
                    .background(badgeColor)
                    .border(
                        width = 1.dp,
                        color = if (palette.isDark) Color(0xCC06080B) else Color(0xE6FFFFFF),
                        shape = CircleShape,
                    ),
            )
        }
    }
}

@Composable
fun AuroraHeroBackground(
    phase: TunnelPhase,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    val colorSpec = tween<Color>(durationMillis = 680)

    val baseTop by animateColorAsState(
        targetValue = when (phase) {
            TunnelPhase.CONNECTED -> Color(0xFF06283D)
            TunnelPhase.CONNECTING -> Color(0xFF181E38)
            TunnelPhase.ERROR -> Color(0xFF2E0B14)
            TunnelPhase.DISCONNECTED -> if (palette.isDark) Color(0xFF141821) else Color(0xFFE2E8F0)
        },
        animationSpec = colorSpec,
        label = "auroraBaseTop",
    )
    val baseBottom by animateColorAsState(
        targetValue = when (phase) {
            TunnelPhase.CONNECTED -> Color(0xFF041C2C)
            TunnelPhase.CONNECTING -> Color(0xFF0E1326)
            TunnelPhase.ERROR -> Color(0xFF19060B)
            TunnelPhase.DISCONNECTED -> if (palette.isDark) Color(0xFF0B0E15) else Color(0xFFD5DFEC)
        },
        animationSpec = colorSpec,
        label = "auroraBaseBottom",
    )
    val orbPrimary by animateColorAsState(
        targetValue = when (phase) {
            TunnelPhase.CONNECTED -> Color(0xFF00D26A)
            TunnelPhase.CONNECTING -> Color(0xFFF59E0B)
            TunnelPhase.ERROR -> Color(0xFFFF4D6D)
            TunnelPhase.DISCONNECTED -> if (palette.isDark) Color(0xFF334155) else Color(0xFF94A3B8)
        },
        animationSpec = colorSpec,
        label = "auroraOrbPrimary",
    )
    val orbSecondary by animateColorAsState(
        targetValue = when (phase) {
            TunnelPhase.CONNECTED -> Color(0xFF00C2D1)
            TunnelPhase.CONNECTING -> Color(0xFF19C8FF)
            TunnelPhase.ERROR -> Color(0xFFB91C1C)
            TunnelPhase.DISCONNECTED -> if (palette.isDark) Color(0xFF1E293B) else Color(0xFF64748B)
        },
        animationSpec = colorSpec,
        label = "auroraOrbSecondary",
    )

    val transition = rememberInfiniteTransition(label = "auroraMesh")
    val slowPhase by transition.animateFloat(
        initialValue = 0f,
        targetValue = (2.0 * PI).toFloat(),
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 15000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart,
        ),
        label = "auroraSlowOrbit",
    )
    val fastPhase by transition.animateFloat(
        initialValue = 0f,
        targetValue = (2.0 * PI).toFloat(),
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 6800, easing = LinearEasing),
            repeatMode = RepeatMode.Restart,
        ),
        label = "auroraFastOrbit",
    )
    val pulse by transition.animateFloat(
        initialValue = 0.88f,
        targetValue = 1.08f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 4800, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "auroraPulse",
    )

    val activeAngle = if (phase == TunnelPhase.CONNECTING) fastPhase else slowPhase
    val dotColor = if (phase == TunnelPhase.DISCONNECTED && !palette.isDark) {
        Color(0xFF0F172A).copy(alpha = 0.05f)
    } else {
        Color.White.copy(alpha = 0.05f)
    }

    Canvas(modifier = modifier.fillMaxSize()) {
        val w = size.width
        val h = size.height
        if (w <= 0f || h <= 0f) return@Canvas
        val maxDim = max(w, h)

        // Base atmospheric gradient
        drawRect(
            brush = Brush.verticalGradient(
                colors = listOf(baseTop, baseBottom),
            ),
        )

        val primaryAlpha = when (phase) {
            TunnelPhase.CONNECTED -> 0.42f
            TunnelPhase.CONNECTING -> 0.36f
            TunnelPhase.ERROR -> 0.38f
            TunnelPhase.DISCONNECTED -> if (palette.isDark) 0.28f else 0.24f
        }
        val secondaryAlpha = when (phase) {
            TunnelPhase.CONNECTED -> 0.34f
            TunnelPhase.CONNECTING -> 0.34f
            TunnelPhase.ERROR -> 0.32f
            TunnelPhase.DISCONNECTED -> if (palette.isDark) 0.24f else 0.18f
        }

        val orbitRadiusX = w * 0.18f
        val orbitRadiusY = h * 0.14f

        val orb1Center = Offset(
            x = w * 0.24f + cos(activeAngle) * orbitRadiusX,
            y = h * 0.28f + sin(activeAngle) * orbitRadiusY,
        )
        val orb2Center = Offset(
            x = w * 0.78f + cos(activeAngle + 2.35f) * orbitRadiusX,
            y = h * 0.64f + sin(activeAngle + 2.35f) * orbitRadiusY,
        )
        val orb3Center = Offset(
            x = w * 0.56f + sin(activeAngle * 0.7f) * (w * 0.14f),
            y = h * 0.16f + cos(activeAngle * 0.7f) * (h * 0.10f),
        )

        drawRect(
            brush = Brush.radialGradient(
                colors = listOf(
                    orbPrimary.copy(alpha = primaryAlpha),
                    orbPrimary.copy(alpha = primaryAlpha * 0.35f),
                    Color.Transparent,
                ),
                center = orb1Center,
                radius = maxDim * 0.72f * pulse,
            ),
        )

        drawRect(
            brush = Brush.radialGradient(
                colors = listOf(
                    orbSecondary.copy(alpha = secondaryAlpha),
                    orbSecondary.copy(alpha = secondaryAlpha * 0.30f),
                    Color.Transparent,
                ),
                center = orb2Center,
                radius = maxDim * 0.68f,
            ),
        )

        drawRect(
            brush = Brush.radialGradient(
                colors = listOf(
                    lerp(orbPrimary, orbSecondary, 0.5f).copy(alpha = secondaryAlpha * 0.65f),
                    Color.Transparent,
                ),
                center = orb3Center,
                radius = maxDim * 0.52f,
            ),
        )

        // Subtle tactical dot-matrix texture (0.05 alpha)
        val stepPx = 14.dp.toPx()
        val dotRadius = 0.9.dp.toPx()
        var y = stepPx * 0.5f
        while (y < h) {
            var x = stepPx * 0.5f
            while (x < w) {
                drawCircle(
                    color = dotColor,
                    radius = dotRadius,
                    center = Offset(x, y),
                )
                x += stepPx
            }
            y += stepPx
        }
    }
}

@Composable
fun AmbientCanvasBackdrop(
    phase: TunnelPhase,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    val colorSpec = tween<Color>(durationMillis = 720)

    val primaryWash by animateColorAsState(
        targetValue = when (phase) {
            TunnelPhase.CONNECTED -> palette.signal.copy(alpha = if (palette.isDark) 0.13f else 0.10f)
            TunnelPhase.CONNECTING -> palette.warning.copy(alpha = if (palette.isDark) 0.12f else 0.09f)
            TunnelPhase.ERROR -> palette.danger.copy(alpha = if (palette.isDark) 0.13f else 0.09f)
            TunnelPhase.DISCONNECTED -> palette.accent.copy(alpha = if (palette.isDark) 0.06f else 0.06f)
        },
        animationSpec = colorSpec,
        label = "ambientPrimaryWash",
    )
    val secondaryWash by animateColorAsState(
        targetValue = when (phase) {
            TunnelPhase.CONNECTED -> palette.accent.copy(alpha = if (palette.isDark) 0.10f else 0.08f)
            TunnelPhase.CONNECTING -> palette.accent.copy(alpha = if (palette.isDark) 0.10f else 0.07f)
            TunnelPhase.ERROR -> Color(0xFFB91C1C).copy(alpha = if (palette.isDark) 0.09f else 0.06f)
            TunnelPhase.DISCONNECTED -> palette.inkMuted.copy(alpha = if (palette.isDark) 0.05f else 0.05f)
        },
        animationSpec = colorSpec,
        label = "ambientSecondaryWash",
    )

    Canvas(modifier = modifier.fillMaxSize()) {
        val w = size.width
        val h = size.height
        if (w <= 0f || h <= 0f) return@Canvas

        drawRect(color = palette.canvas)

        drawRect(
            brush = Brush.radialGradient(
                colors = listOf(primaryWash, Color.Transparent),
                center = Offset(x = w * 0.22f, y = h * 0.04f),
                radius = max(w, h) * 0.72f,
            ),
        )

        drawRect(
            brush = Brush.radialGradient(
                colors = listOf(secondaryWash, Color.Transparent),
                center = Offset(x = w * 0.85f, y = h * 0.16f),
                radius = max(w, h) * 0.58f,
            ),
        )
    }
}
