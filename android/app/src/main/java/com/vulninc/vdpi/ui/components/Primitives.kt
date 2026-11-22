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
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vulninc.vdpi.ui.theme.GeistMono
import com.vulninc.vdpi.ui.theme.GeistSans
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
    content: @Composable ColumnScope.() -> Unit,
) {
    val shape = RoundedCornerShape(radius)
    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(shape)
            .background(backgroundColor)
            .border(1.dp, borderColor, shape),
        content = content,
    )
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
        fontFamily = GeistMono,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        letterSpacing = 0.9.sp,
        color = palette.inkMuted,
    )
}

@Composable
fun PrecisionSwitch(
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
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
        checked && useSignalAccent -> Color(0xFF04130D)
        checked -> palette.canvas
        else -> palette.inkSecondary
    }
    val thumbOffset by animateDpAsState(
        targetValue = if (checked) 20.dp else 2.dp,
        animationSpec = spring(stiffness = Spring.StiffnessMediumLow, dampingRatio = 0.8f),
        label = "switchThumb",
    )

    Box(
        modifier = modifier
            .size(width = 44.dp, height = 26.dp)
            .clip(CircleShape)
            .background(trackColor)
            .border(1.dp, borderColor, CircleShape)
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
            ) {
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                onCheckedChange(!checked)
            },
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
            Box(
                modifier = Modifier
                    .weight(1f)
                    .height(34.dp)
                    .clip(itemShape)
                    .background(if (isSelected) palette.surfaceRaised else Color.Transparent)
                    .border(
                        width = if (isSelected) 1.dp else 0.dp,
                        color = if (isSelected) palette.borderStrong else Color.Transparent,
                        shape = itemShape,
                    )
                    .clickable { onSelect(option) },
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
) {
    val palette = VdpiThemeTokens.palette
    val shape = RoundedCornerShape(10.dp)

    Row(
        modifier = modifier
            .height(44.dp)
            .clip(shape)
            .background(palette.surface)
            .border(1.dp, palette.border, shape)
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp),
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
                fontFamily = GeistMono,
                fontSize = 11.sp,
                color = palette.inkMuted,
            )
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
        val stroke = Stroke(width = 1.6.dp.toPx(), cap = StrokeCap.Round)
        val w = size.width
        val h = size.height
        when (kind) {
            TabIconKind.TUNNEL -> {
                drawLine(tint, Offset(w * 0.16f, h * 0.34f), Offset(w * 0.44f, h * 0.34f), stroke.width, StrokeCap.Round)
                drawLine(tint, Offset(w * 0.56f, h * 0.34f), Offset(w * 0.84f, h * 0.34f), stroke.width, StrokeCap.Round)
                drawLine(tint, Offset(w * 0.16f, h * 0.66f), Offset(w * 0.84f, h * 0.66f), stroke.width, StrokeCap.Round)
            }
            TabIconKind.APPS -> {
                val r = w * 0.16f
                val positions = listOf(
                    Offset(w * 0.28f, h * 0.28f),
                    Offset(w * 0.72f, h * 0.28f),
                    Offset(w * 0.28f, h * 0.72f),
                    Offset(w * 0.72f, h * 0.72f),
                )
                positions.forEach { c ->
                    drawCircle(tint, radius = r, center = c, style = stroke)
                }
            }
            TabIconKind.SETTINGS -> {
                drawLine(tint, Offset(w * 0.14f, h * 0.30f), Offset(w * 0.86f, h * 0.30f), stroke.width, StrokeCap.Round)
                drawCircle(tint, radius = 2.6.dp.toPx(), center = Offset(w * 0.36f, h * 0.30f))
                drawLine(tint, Offset(w * 0.14f, h * 0.70f), Offset(w * 0.86f, h * 0.70f), stroke.width, StrokeCap.Round)
                drawCircle(tint, radius = 2.6.dp.toPx(), center = Offset(w * 0.66f, h * 0.70f))
            }
        }
    }
}

enum class TabIconKind {
    TUNNEL,
    APPS,
    SETTINGS,
}
