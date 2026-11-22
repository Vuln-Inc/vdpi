package com.vulninc.vdpi.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
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
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vulninc.vdpi.ui.theme.GeistMono
import com.vulninc.vdpi.ui.theme.GeistSans
import com.vulninc.vdpi.ui.theme.VdpiTextStyles
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens

/**
 * Custom geometric vdpi brand mark: fractured V symbolizing TLS packet splitting
 * above a crisp signal bar that lights emerald only when active.
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

    Canvas(modifier = modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height

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
    radius: Dp = 12.dp,
    topHighlight: Boolean = false,
    content: @Composable ColumnScope.() -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val shape = RoundedCornerShape(radius)
    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(shape)
            .background(backgroundColor)
            .border(1.dp, borderColor, shape),
    ) {
        if (topHighlight && palette.topHighlight != Color.Transparent) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(1.dp)
                    .background(palette.topHighlight),
            )
        }
        content()
    }
}

@Composable
fun HairlineRule(modifier: Modifier = Modifier) {
    HorizontalDivider(
        modifier = modifier,
        thickness = 1.dp,
        color = VdpiThemeTokens.palette.border,
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
 * Symmetrically balanced precision toggle switch.
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
    val trackColor by animateColorAsState(
        targetValue = when {
            checked && useSignalAccent -> palette.signal
            checked -> palette.inkPrimary
            else -> palette.surfaceRaised
        },
        animationSpec = tween(180),
        label = "switchTrack",
    )
    val borderColor by animateColorAsState(
        targetValue = if (checked) Color.Transparent else palette.borderStrong,
        animationSpec = tween(180),
        label = "switchBorder",
    )
    val thumbColor = when {
        checked && useSignalAccent -> if (palette.isDark) Color(0xFF04130D) else Color.White
        checked -> palette.canvas
        else -> palette.inkSecondary
    }
    // 44dp track, 20dp thumb -> 3dp left padding, 21dp checked offset -> 3dp right padding (exact symmetry).
    val thumbOffset by animateDpAsState(
        targetValue = if (checked) 21.dp else 3.dp,
        animationSpec = spring(stiffness = Spring.StiffnessMediumLow, dampingRatio = 0.82f),
        label = "switchThumb",
    )

    val interactiveModifier = if (onCheckedChange != null) {
        modifier.clickable(
            interactionSource = remember { MutableInteractionSource() },
            indication = null,
            role = Role.Switch,
        ) {
            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
            onCheckedChange(!checked)
        }
    } else {
        modifier
    }

    Box(
        modifier = interactiveModifier
            .size(width = 44.dp, height = 26.dp)
            .clip(CircleShape)
            .background(trackColor)
            .border(1.dp, borderColor, CircleShape),
        contentAlignment = Alignment.CenterStart,
    ) {
        Box(
            modifier = Modifier
                .offset { IntOffset(thumbOffset.roundToPx(), 0) }
                .size(20.dp)
                .clip(CircleShape)
                .background(thumbColor),
        )
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
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val containerShape = RoundedCornerShape(10.dp)
    val itemShape = RoundedCornerShape(7.dp)

    Row(
        modifier = modifier
            .fillMaxWidth()
            .clip(containerShape)
            .background(palette.surface)
            .border(1.dp, palette.border, containerShape)
            .padding(3.dp),
        horizontalArrangement = Arrangement.spacedBy(3.dp),
    ) {
        options.forEach { option ->
            val isSelected = option == selected
            val itemBg by animateColorAsState(
                targetValue = if (isSelected) palette.surfaceRaised else Color.Transparent,
                animationSpec = tween(160),
                label = "segBg",
            )
            val itemBorder by animateColorAsState(
                targetValue = if (isSelected) palette.borderStrong else Color.Transparent,
                animationSpec = tween(160),
                label = "segBorder",
            )
            Box(
                modifier = Modifier
                    .weight(1f)
                    .height(44.dp)
                    .clip(itemShape)
                    .background(itemBg)
                    .border(
                        width = if (isSelected) 1.dp else 0.dp,
                        color = itemBorder,
                        shape = itemShape,
                    )
                    .selectable(
                        selected = isSelected,
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
                    fontWeight = if (isSelected) FontWeight.Medium else FontWeight.Normal,
                    fontSize = 13.sp,
                    color = if (isSelected) palette.inkPrimary else palette.inkSecondary,
                )
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
    val shape = RoundedCornerShape(10.dp)

    Row(
        modifier = modifier
            .heightIn(min = 44.dp)
            .alpha(if (enabled) 1f else 0.45f)
            .clip(shape)
            .background(palette.surface)
            .border(1.dp, palette.border, shape)
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 10.dp),
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
    val shape = RoundedCornerShape(10.dp)
    SnackbarHost(
        hostState = hostState,
        modifier = modifier.padding(horizontal = 20.dp, vertical = 10.dp),
    ) { data ->
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(shape)
                .background(if (palette.isDark) palette.surfaceRaised else palette.inkPrimary)
                .border(1.dp, palette.borderStrong, shape)
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = data.visuals.message,
                style = VdpiTextStyles.body,
                color = if (palette.isDark) palette.inkPrimary else palette.canvas,
                modifier = Modifier.weight(1f),
            )
            data.visuals.actionLabel?.let { action ->
                Spacer(Modifier.width(8.dp))
                Box(
                    modifier = Modifier
                        .heightIn(min = 44.dp)
                        .clip(RoundedCornerShape(6.dp))
                        .clickable(role = Role.Button) { data.performAction() }
                        .padding(horizontal = 10.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = action,
                        fontFamily = GeistSans,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 13.sp,
                        color = if (palette.isDark) palette.signal else Color(0xFF34D399),
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
