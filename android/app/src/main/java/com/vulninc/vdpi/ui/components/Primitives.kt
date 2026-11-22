package com.vulninc.vdpi.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vulninc.vdpi.ui.theme.GeistSans
import com.vulninc.vdpi.ui.theme.VdpiTextStyles
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens

/**
 * Custom geometric vdpi brand mark: fractured V symbolizing TLS packet splitting
 * above a crisp signal bar that lights emerald with a subtle radial glow when active.
 */
@Composable
fun VdpiBrandMark(
    active: Boolean,
    modifier: Modifier = Modifier,
    size: Dp = 22.dp,
) {
    val palette = VdpiThemeTokens.palette
    val barColor by animateColorAsState(
        targetValue = if (active) palette.signal else palette.inkMuted,
        animationSpec = tween(220),
        label = "brandBar",
    )
    val glowAlpha by animateFloatAsState(
        targetValue = if (active) 1f else 0f,
        animationSpec = tween(320),
        label = "brandGlow",
    )

    Canvas(modifier = modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height

        if (glowAlpha > 0.01f) {
            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(
                        palette.signalGlow.copy(alpha = palette.signalGlow.alpha * glowAlpha),
                        Color.Transparent,
                    ),
                    center = Offset(w * 0.50f, h * 0.78f),
                    radius = w * 0.62f,
                ),
                radius = w * 0.62f,
                center = Offset(w * 0.50f, h * 0.78f),
            )
        }

        val leftArm = Path().apply {
            moveTo(w * 0.14f, h * 0.18f)
            lineTo(w * 0.30f, h * 0.18f)
            lineTo(w * 0.47f, h * 0.72f)
            lineTo(w * 0.31f, h * 0.72f)
            close()
        }
        val rightArm = Path().apply {
            moveTo(w * 0.53f, h * 0.72f)
            lineTo(w * 0.70f, h * 0.18f)
            lineTo(w * 0.86f, h * 0.18f)
            lineTo(w * 0.69f, h * 0.72f)
            close()
        }
        val bar = Path().apply {
            moveTo(w * 0.31f, h * 0.82f)
            lineTo(w * 0.69f, h * 0.82f)
            lineTo(w * 0.69f, h * 0.90f)
            lineTo(w * 0.31f, h * 0.90f)
            close()
        }

        drawPath(leftArm, color = palette.inkPrimary)
        drawPath(rightArm, color = palette.inkPrimary)
        drawPath(bar, color = barColor)
    }
}

@Composable
fun HairlinePanel(
    modifier: Modifier = Modifier,
    borderColor: Color = VdpiThemeTokens.palette.border,
    backgroundColor: Color = VdpiThemeTokens.palette.surface,
    radius: Dp = 18.dp,
    topHighlight: Boolean = false,
    content: @Composable ColumnScope.() -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val shape = RoundedCornerShape(radius)

    val useCustomFill = backgroundColor != palette.surface
    val resolvedFill = if (useCustomFill) backgroundColor else palette.glassFill
    val useCustomRim = borderColor != palette.border

    val rimTop = if (useCustomRim) {
        lerp(palette.glassRimTop, borderColor.copy(alpha = if (palette.isDark) 0.72f else 0.64f), 0.62f)
    } else {
        palette.glassRimTop
    }
    val rimSide = if (useCustomRim) {
        lerp(palette.glassRimSide, borderColor.copy(alpha = if (palette.isDark) 0.34f else 0.28f), 0.55f)
    } else {
        palette.glassRimSide
    }
    val rimBottom = if (useCustomRim) {
        lerp(palette.glassRimBottom, borderColor.copy(alpha = if (palette.isDark) 0.45f else 0.36f), 0.55f)
    } else {
        palette.glassRimBottom
    }

    val specularBorder = remember(rimTop, rimSide, rimBottom) {
        Brush.verticalGradient(
            0.00f to rimTop,
            0.36f to rimSide,
            0.78f to rimSide,
            1.00f to rimBottom,
        )
    }
    val sheenStrength = if (topHighlight) 1.35f else 0.85f
    val sheenTopColor = palette.glassSheenTop.copy(
        alpha = (palette.glassSheenTop.alpha * sheenStrength).coerceAtMost(0.95f),
    )

    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(shape)
            .drawBehind {
                drawRect(
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            resolvedFill.copy(alpha = (resolvedFill.alpha * 1.04f).coerceAtMost(0.96f)),
                            resolvedFill.copy(alpha = (resolvedFill.alpha * 0.92f).coerceAtLeast(0.08f)),
                        ),
                    ),
                )
                if (size.height > 0f) {
                    drawRect(
                        brush = Brush.verticalGradient(
                            colorStops = arrayOf(
                                0.00f to sheenTopColor,
                                0.34f to Color.Transparent,
                            ),
                            startY = 0f,
                            endY = size.height,
                        ),
                    )
                }
            }
            .border(width = 1.dp, brush = specularBorder, shape = shape),
        content = content,
    )
}

@Composable
fun HairlineRule(modifier: Modifier = Modifier) {
    val palette = VdpiThemeTokens.palette
    val ruleBrush = remember(palette.border) {
        Brush.horizontalGradient(
            0.00f to palette.border.copy(alpha = palette.border.alpha * 0.15f),
            0.12f to palette.border,
            0.88f to palette.border,
            1.00f to palette.border.copy(alpha = palette.border.alpha * 0.15f),
        )
    }
    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(1.dp)
            .background(ruleBrush),
    )
}

@Composable
fun SectionOverline(
    text: String,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    Text(
        text = text.uppercase(),
        modifier = modifier,
        style = VdpiTextStyles.overline,
        color = palette.inkMuted,
    )
}

/**
 * iOS-26 / BitChord inspired tactile pill toggle switch with press-stretch thumb physics
 * and emerald glow when active with signal accent.
 * Pass `onCheckedChange = null` when embedded inside a `Modifier.toggleable` row to avoid
 * duplicate TalkBack focus targets.
 */
@Composable
fun PrecisionSwitch(
    checked: Boolean,
    modifier: Modifier = Modifier,
    onCheckedChange: ((Boolean) -> Unit)? = null,
    useSignalAccent: Boolean = false,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()

    val progress by animateFloatAsState(
        targetValue = if (checked) 1f else 0f,
        animationSpec = VdpiMotion.toggleSpring,
        label = "switchProgress",
    )
    val pressStretch by animateFloatAsState(
        targetValue = if (isPressed) 1f else 0f,
        animationSpec = VdpiMotion.toggleSpring,
        label = "switchThumbStretch",
    )

    val trackColor by animateColorAsState(
        targetValue = when {
            checked && useSignalAccent -> palette.signal
            checked -> palette.inkPrimary
            else -> palette.glassFillSubtle
        },
        animationSpec = tween(200),
        label = "switchTrack",
    )
    val thumbColor by animateColorAsState(
        targetValue = when {
            checked && useSignalAccent -> palette.signalThumbInk
            checked -> palette.canvas
            else -> if (palette.isDark) Color(0xFFE5EAF2) else palette.surface
        },
        animationSpec = tween(180),
        label = "switchThumbColor",
    )

    val trackRim = remember(checked, useSignalAccent, palette) {
        if (checked && useSignalAccent) {
            Brush.verticalGradient(
                0.0f to Color.White.copy(alpha = 0.45f),
                0.5f to Color.Transparent,
                1.0f to palette.signalBorder,
            )
        } else if (checked) {
            Brush.verticalGradient(
                0.0f to palette.glassRimTop.copy(alpha = 0.35f),
                1.0f to Color.Transparent,
            )
        } else {
            Brush.verticalGradient(
                0.0f to palette.glassRimTop,
                0.45f to palette.glassRimSide,
                1.0f to palette.glassRimBottom,
            )
        }
    }

    val interactiveModifier = if (onCheckedChange != null) {
        modifier
            .defaultMinSize(minWidth = 48.dp, minHeight = 48.dp)
            .clickable(
                interactionSource = interactionSource,
                indication = null,
                role = Role.Switch,
            ) {
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                onCheckedChange(!checked)
            }
    } else {
        modifier
    }

    // 54dp x 30dp capsule track, 3dp padding -> 24dp tall pill thumb (28dp resting, 33dp stretched).
    val thumbWidth = (28f + 5f * pressStretch).dp
    val maxTravel = 54.dp - 6.dp - thumbWidth
    val thumbOffset = 3.dp + maxTravel * progress

    val trackShadowModifier = if (checked && useSignalAccent) {
        Modifier.shadow(
            elevation = 10.dp,
            shape = CircleShape,
            clip = false,
            ambientColor = palette.signalGlow,
            spotColor = palette.signalGlow,
        )
    } else {
        Modifier
    }

    Box(
        modifier = interactiveModifier,
        contentAlignment = Alignment.Center,
    ) {
        Box(
            modifier = Modifier
                .then(trackShadowModifier)
                .size(width = 54.dp, height = 30.dp)
                .clip(CircleShape)
                .background(trackColor)
                .border(width = 1.dp, brush = trackRim, shape = CircleShape),
            contentAlignment = Alignment.CenterStart,
        ) {
            Box(
                modifier = Modifier
                    .offset { IntOffset(thumbOffset.roundToPx(), 0) }
                    .shadow(
                        elevation = 3.dp,
                        shape = CircleShape,
                        clip = false,
                        ambientColor = Color.Black.copy(alpha = 0.28f),
                        spotColor = Color.Black.copy(alpha = 0.28f),
                    )
                    .size(width = thumbWidth, height = 24.dp)
                    .clip(CircleShape)
                    .background(thumbColor)
                    .drawBehind {
                        drawRect(
                            brush = Brush.verticalGradient(
                                0.0f to Color.White.copy(alpha = if (palette.isDark) 0.22f else 0.45f),
                                0.5f to Color.Transparent,
                            ),
                        )
                    },
            )
        }
    }
}

@Composable
fun <T> SegmentedControl(
    options: List<T>,
    selected: T,
    labelFor: (T) -> String,
    onSelect: (T) -> Unit,
    modifier: Modifier = Modifier,
) {
    if (options.isEmpty()) return

    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val selectedIndex = options.indexOf(selected).coerceAtLeast(0)

    val lensRim = remember(palette.glassRimTop, palette.glassRimSide, palette.glassRimBottom) {
        Brush.verticalGradient(
            0.00f to palette.glassRimTop,
            0.40f to palette.glassRimSide,
            1.00f to palette.glassRimBottom,
        )
    }

    BoxWithConstraints(
        modifier = modifier
            .fillMaxWidth()
            .liquidGlass(
                shape = CircleShape,
                elevated = false,
                fillTint = palette.glassFillSubtle,
            )
            .padding(3.dp),
    ) {
        val segmentWidth = maxWidth / options.size
        val indicatorOffset by animateDpAsState(
            targetValue = segmentWidth * selectedIndex,
            animationSpec = VdpiMotion.tabLensSpring,
            label = "segmentedLensOffset",
        )

        // Sliding spring glass lens indicator
        Box(
            modifier = Modifier
                .offset { IntOffset(indicatorOffset.roundToPx(), 0) }
                .width(segmentWidth)
                .height(40.dp)
                .shadow(
                    elevation = if (palette.isDark) 6.dp else 4.dp,
                    shape = CircleShape,
                    clip = false,
                    ambientColor = palette.glassShadow,
                    spotColor = palette.glassShadow,
                )
                .clip(CircleShape)
                .background(palette.glassLensFill)
                .drawBehind {
                    drawRect(
                        brush = Brush.verticalGradient(
                            0.00f to palette.glassSheenTop,
                            0.45f to Color.Transparent,
                        ),
                    )
                }
                .border(width = 1.dp, brush = lensRim, shape = CircleShape),
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            options.forEach { option ->
                val isSelected = option == selected
                val textColor by animateColorAsState(
                    targetValue = if (isSelected) palette.inkPrimary else palette.inkSecondary,
                    animationSpec = tween(160),
                    label = "segmentedLabelColor",
                )
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .height(40.dp)
                        .clip(CircleShape)
                        .selectable(
                            selected = isSelected,
                            interactionSource = remember { MutableInteractionSource() },
                            indication = null,
                            role = Role.Tab,
                            onClick = {
                                if (!isSelected) {
                                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    onSelect(option)
                                }
                            },
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = labelFor(option),
                        fontFamily = GeistSans,
                        fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Medium,
                        fontSize = 13.sp,
                        color = textColor,
                    )
                }
            }
        }
    }
}

@Composable
fun GhostActionButton(
    label: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    trailingMono: String? = null,
    enabled: Boolean = true,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val interactionSource = remember { MutableInteractionSource() }

    Row(
        modifier = modifier
            .heightIn(min = 44.dp)
            .alpha(if (enabled) 1f else 0.45f)
            .springPress(interactionSource = interactionSource, pressedScale = 0.96f)
            .liquidGlass(
                shape = CircleShape,
                elevated = false,
            )
            .clickable(
                interactionSource = interactionSource,
                indication = null,
                enabled = enabled,
                role = Role.Button,
            ) {
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                onClick()
            }
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Center,
    ) {
        Text(
            text = label,
            fontFamily = GeistSans,
            fontWeight = FontWeight.Medium,
            fontSize = 13.sp,
            color = palette.inkPrimary,
        )
        if (trailingMono != null) {
            Spacer(Modifier.width(6.dp))
            Text(
                text = trailingMono,
                style = VdpiTextStyles.monoSmall,
                color = palette.inkMuted,
            )
        }
    }
}

@Composable
fun MinimalSnackbarHost(
    hostState: SnackbarHostState,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    val capsuleShape = RoundedCornerShape(26.dp)
    SnackbarHost(
        hostState = hostState,
        modifier = modifier.padding(horizontal = 20.dp, vertical = 10.dp),
    ) { data ->
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .liquidGlass(
                    shape = capsuleShape,
                    elevated = true,
                )
                .padding(horizontal = 18.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = data.visuals.message,
                style = VdpiTextStyles.body,
                color = palette.inkPrimary,
                modifier = Modifier.weight(1f),
            )
            data.visuals.actionLabel?.let { action ->
                Spacer(Modifier.width(8.dp))
                Box(
                    modifier = Modifier
                        .heightIn(min = 36.dp)
                        .clip(CircleShape)
                        .clickable(role = Role.Button) { data.performAction() }
                        .padding(horizontal = 12.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = action,
                        fontFamily = GeistSans,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 13.sp,
                        color = palette.signal,
                    )
                }
            }
        }
    }
}

@Composable
fun MinimalTabIcon(
    kind: TabIconKind,
    tint: Color,
    modifier: Modifier = Modifier,
) {
    Canvas(modifier = modifier.size(18.dp)) {
        val strokeWidth = 1.6.dp.toPx()
        val stroke = Stroke(width = strokeWidth, cap = StrokeCap.Round, join = StrokeJoin.Round)
        val w = size.width
        val h = size.height
        when (kind) {
            TabIconKind.TUNNEL -> {
                // Crisp fractured-V chevron mirroring the vdpi brand mark
                val left = Path().apply {
                    moveTo(w * 0.16f, h * 0.22f)
                    lineTo(w * 0.43f, h * 0.74f)
                }
                val right = Path().apply {
                    moveTo(w * 0.57f, h * 0.74f)
                    lineTo(w * 0.84f, h * 0.22f)
                }
                drawPath(left, color = tint, style = stroke)
                drawPath(right, color = tint, style = stroke)
                drawLine(
                    color = tint,
                    start = Offset(w * 0.34f, h * 0.86f),
                    end = Offset(w * 0.66f, h * 0.86f),
                    strokeWidth = strokeWidth,
                    cap = StrokeCap.Round,
                )
            }
            TabIconKind.APPS -> {
                // Crisp 2x2 rounded-square grid
                val cell = w * 0.32f
                val corner = CornerRadius(2.2.dp.toPx(), 2.2.dp.toPx())
                val origins = listOf(
                    Offset(w * 0.12f, h * 0.12f),
                    Offset(w * 0.56f, h * 0.12f),
                    Offset(w * 0.12f, h * 0.56f),
                    Offset(w * 0.56f, h * 0.56f),
                )
                origins.forEach { topLeft ->
                    drawRoundRect(
                        color = tint,
                        topLeft = topLeft,
                        size = Size(cell, cell),
                        cornerRadius = corner,
                        style = stroke,
                    )
                }
            }
            TabIconKind.SETTINGS -> {
                drawLine(tint, Offset(w * 0.14f, h * 0.30f), Offset(w * 0.86f, h * 0.30f), strokeWidth, StrokeCap.Round)
                drawCircle(tint, radius = 2.4.dp.toPx(), center = Offset(w * 0.36f, h * 0.30f))
                drawLine(tint, Offset(w * 0.14f, h * 0.70f), Offset(w * 0.86f, h * 0.70f), strokeWidth, StrokeCap.Round)
                drawCircle(tint, radius = 2.4.dp.toPx(), center = Offset(w * 0.66f, h * 0.70f))
            }
        }
    }
}

enum class TabIconKind {
    TUNNEL,
    APPS,
    SETTINGS,
}
