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
import androidx.compose.foundation.layout.fillMaxHeight
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
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Fill
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vulninc.vdpi.ui.theme.GeistSans
import com.vulninc.vdpi.ui.theme.VdpiTextStyles
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens

private val AppleSwitchOnDark = Color(0xFF30D158)
private val AppleSwitchOnLight = Color(0xFF34C759)
private val AppleSwitchOffDark = Color(0xFF39393D)
private val AppleSwitchOffLight = Color(0xFFE9E9EB)
private val AppleSegmentedThumbDark = Color(0xFF636366)
private val AppleSegmentedThumbLight = Color(0xFFFFFFFF)

/**
 * Crisp geometric vdpi brand mark: fractured V symbolizing TLS packet splitting
 * above a clean signal bar tinted with `palette.signal` when active.
 */
@Composable
fun VdpiBrandMark(
    active: Boolean,
    modifier: Modifier = Modifier,
    size: Dp = 22.dp,
) {
    val palette = VdpiThemeTokens.palette
    val signalStrokeColor by animateColorAsState(
        targetValue = if (active) palette.signal else palette.inkPrimary,
        animationSpec = tween(200),
        label = "brandSignalBar",
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
        drawPath(bar, color = signalStrokeColor)
    }
}

/**
 * Opaque Apple Inset Grouped surface container.
 * Uses no outer border, drop shadow, or top highlight unless a caller explicitly supplies
 * a non-default alert [borderColor].
 */
@Composable
fun HairlinePanel(
    modifier: Modifier = Modifier,
    borderColor: Color = VdpiThemeTokens.palette.border,
    backgroundColor: Color = VdpiThemeTokens.palette.surface,
    radius: Dp = 16.dp,
    @Suppress("UNUSED_PARAMETER") topHighlight: Boolean = false,
    content: @Composable ColumnScope.() -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val shape = RoundedCornerShape(radius)
    val showAlertBorder = borderColor != palette.border && borderColor != Color.Transparent

    val borderModifier = if (showAlertBorder) {
        Modifier.border(width = 1.dp, color = borderColor, shape = shape)
    } else {
        Modifier
    }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(shape)
            .background(backgroundColor)
            .then(borderModifier),
        content = content,
    )
}

/**
 * Crisp 0.5dp Apple Inset Grouped separator with optional leading inset.
 */
@Composable
fun HairlineRule(
    modifier: Modifier = Modifier,
    startIndent: Dp = 0.dp,
) {
    val palette = VdpiThemeTokens.palette
    val ruleColor = palette.border.copy(alpha = palette.border.alpha * 0.65f)
    Box(
        modifier = modifier
            .fillMaxWidth()
            .padding(start = startIndent)
            .height(0.5.dp)
            .background(ruleColor),
    )
}

/**
 * Apple Inset Grouped section header label.
 */
@Composable
fun SectionOverline(
    text: String,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    Text(
        text = text,
        modifier = modifier.padding(start = 16.dp, end = 16.dp, bottom = 7.dp),
        style = VdpiTextStyles.caption.copy(letterSpacing = 0.sp),
        color = palette.inkMuted,
    )
}

/**
 * Apple Inset Grouped explanatory section footer.
 */
@Composable
fun SectionFooter(
    text: String,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    Text(
        text = text,
        modifier = modifier.padding(start = 16.dp, end = 16.dp, top = 7.dp),
        style = VdpiTextStyles.caption,
        color = palette.inkMuted,
    )
}

/**
 * Apple Settings Inset Grouped list row with quiet press highlight wash,
 * optional subtitle, leading/trailing accessories, and secondary trailing value.
 */
@Composable
fun InsetGroupedRow(
    title: String,
    modifier: Modifier = Modifier,
    subtitle: String? = null,
    trailingText: String? = null,
    onClick: (() -> Unit)? = null,
    leading: (@Composable () -> Unit)? = null,
    trailing: (@Composable () -> Unit)? = null,
) {
    val palette = VdpiThemeTokens.palette
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()
    val pressWash by animateColorAsState(
        targetValue = if (onClick != null && isPressed) {
            palette.inkPrimary.copy(alpha = 0.06f)
        } else {
            Color.Transparent
        },
        animationSpec = tween(durationMillis = if (isPressed) 60 else 180),
        label = "insetGroupedRowPressWash",
    )

    val clickModifier = if (onClick != null) {
        Modifier.clickable(
            interactionSource = interactionSource,
            indication = null,
            role = Role.Button,
            onClick = onClick,
        )
    } else {
        Modifier
    }

    Row(
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = 50.dp)
            .background(pressWash)
            .then(clickModifier)
            .padding(horizontal = 16.dp, vertical = 11.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (leading != null) {
            leading()
            Spacer(Modifier.width(12.dp))
        }

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = VdpiTextStyles.rowTitle,
                color = palette.inkPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (subtitle != null) {
                Spacer(Modifier.height(2.dp))
                Text(
                    text = subtitle,
                    style = VdpiTextStyles.caption,
                    color = palette.inkSecondary,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }

        if (trailingText != null || trailing != null) {
            Spacer(Modifier.width(12.dp))
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (trailingText != null) {
                    Text(
                        text = trailingText,
                        style = VdpiTextStyles.body,
                        color = palette.inkSecondary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                if (trailing != null) {
                    trailing()
                }
            }
        }
    }
}

/**
 * Native-feel iOS / BitChord switch (51dp x 31dp track, 27dp white thumb with subtle
 * press stretch to 31dp). Pass `onCheckedChange = null` when embedded inside a
 * `Modifier.toggleable` row to avoid duplicate TalkBack focus targets.
 */
@Composable
fun PrecisionSwitch(
    checked: Boolean,
    modifier: Modifier = Modifier,
    onCheckedChange: ((Boolean) -> Unit)? = null,
    @Suppress("UNUSED_PARAMETER") useSignalAccent: Boolean = false,
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
            checked && palette.isDark -> AppleSwitchOnDark
            checked -> AppleSwitchOnLight
            palette.isDark -> AppleSwitchOffDark
            else -> AppleSwitchOffLight
        },
        animationSpec = tween(180),
        label = "switchTrack",
    )

    val interactiveModifier = if (onCheckedChange != null) {
        modifier
            .defaultMinSize(minWidth = 51.dp, minHeight = 48.dp)
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

    // 51dp x 31dp capsule track, 2dp inset -> 27dp circular thumb (stretches to 31dp while pressed).
    val thumbWidth = (27f + 4f * pressStretch).dp
    val maxTravel = 51.dp - 4.dp - thumbWidth
    val thumbOffset = 2.dp + maxTravel * progress

    Box(
        modifier = interactiveModifier,
        contentAlignment = Alignment.Center,
    ) {
        Box(
            modifier = Modifier
                .size(width = 51.dp, height = 31.dp)
                .clip(CircleShape)
                .background(trackColor),
            contentAlignment = Alignment.CenterStart,
        ) {
            Box(
                modifier = Modifier
                    .offset { IntOffset(thumbOffset.roundToPx(), 0) }
                    .shadow(
                        elevation = 3.dp,
                        shape = CircleShape,
                        clip = false,
                        ambientColor = Color.Black.copy(alpha = 0.18f),
                        spotColor = Color.Black.copy(alpha = 0.24f),
                    )
                    .size(width = thumbWidth, height = 27.dp)
                    .clip(CircleShape)
                    .background(Color.White),
            )
        }
    }
}

/**
 * Apple Segmented Control with recessed neutral track, subtle inter-segment dividers,
 * and a spring-sliding solid active segment.
 */
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
    val trackShape = RoundedCornerShape(10.dp)
    val thumbShape = RoundedCornerShape(8.dp)
    val thumbColor = if (palette.isDark) AppleSegmentedThumbDark else AppleSegmentedThumbLight
    val dividerColor = palette.inkPrimary.copy(alpha = if (palette.isDark) 0.14f else 0.12f)

    BoxWithConstraints(
        modifier = modifier
            .fillMaxWidth()
            .clip(trackShape)
            .background(palette.surfaceRaised)
            .padding(2.dp),
    ) {
        val segmentWidth = maxWidth / options.size
        val indicatorOffset by animateDpAsState(
            targetValue = segmentWidth * selectedIndex,
            animationSpec = VdpiMotion.tabLensSpring,
            label = "segmentedThumbOffset",
        )

        // Subtle vertical dividers between unselected adjacent segments
        for (idx in 0 until options.size - 1) {
            val showDivider = idx != selectedIndex && idx + 1 != selectedIndex
            val dividerAlpha by animateFloatAsState(
                targetValue = if (showDivider) 1f else 0f,
                animationSpec = tween(140),
                label = "segmentedDividerAlpha_$idx",
            )
            if (dividerAlpha > 0.01f) {
                Box(
                    modifier = Modifier
                        .align(Alignment.CenterStart)
                        .offset { IntOffset((segmentWidth * (idx + 1)).roundToPx(), 0) }
                        .width(0.5.dp)
                        .height(14.dp)
                        .alpha(dividerAlpha)
                        .background(dividerColor),
                )
            }
        }

        // Solid spring-sliding active segment
        Box(modifier = Modifier.matchParentSize()) {
            Box(
                modifier = Modifier
                    .offset { IntOffset(indicatorOffset.roundToPx(), 0) }
                    .width(segmentWidth)
                    .fillMaxHeight()
                    .heightIn(min = 34.dp)
                    .shadow(
                        elevation = 2.dp,
                        shape = thumbShape,
                        clip = false,
                        ambientColor = Color.Black.copy(alpha = if (palette.isDark) 0.24f else 0.10f),
                        spotColor = Color.Black.copy(alpha = if (palette.isDark) 0.30f else 0.14f),
                    )
                    .clip(thumbShape)
                    .background(thumbColor),
            )
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            options.forEach { option ->
                val isSelected = option == selected
                val textColor by animateColorAsState(
                    targetValue = if (isSelected) palette.inkPrimary else palette.inkSecondary,
                    animationSpec = tween(150),
                    label = "segmentedLabelColor",
                )
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 34.dp)
                        .clip(thumbShape)
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
                        )
                        .padding(horizontal = 6.dp, vertical = 4.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = labelFor(option),
                        fontFamily = GeistSans,
                        fontWeight = FontWeight.Medium,
                        fontSize = 13.sp,
                        color = textColor,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }
    }
}

/**
 * Clean Apple tonal secondary pill button without decorative glass border.
 */
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
    val isPressed by interactionSource.collectIsPressedAsState()
    val pressWash by animateColorAsState(
        targetValue = if (enabled && isPressed) {
            palette.inkPrimary.copy(alpha = 0.06f)
        } else {
            Color.Transparent
        },
        animationSpec = tween(durationMillis = if (isPressed) 60 else 160),
        label = "ghostActionPressWash",
    )

    Row(
        modifier = modifier
            .heightIn(min = 44.dp)
            .alpha(if (enabled) 1f else 0.45f)
            .springPress(interactionSource = interactionSource, pressedScale = 0.97f)
            .clip(CircleShape)
            .background(palette.surfaceRaised)
            .background(pressWash)
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
            fontSize = 14.sp,
            color = palette.inkPrimary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        if (trailingMono != null) {
            Spacer(Modifier.width(6.dp))
            Text(
                text = trailingMono,
                style = VdpiTextStyles.monoSmall,
                color = palette.inkSecondary,
                maxLines = 1,
            )
        }
    }
}

/**
 * Floating Liquid Glass snackbar capsule with compact layout and a single
 * high-contrast accent action button.
 */
@Composable
fun MinimalSnackbarHost(
    hostState: SnackbarHostState,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    val capsuleShape = RoundedCornerShape(24.dp)
    SnackbarHost(
        hostState = hostState,
        modifier = modifier.padding(horizontal = 20.dp, vertical = 8.dp),
    ) { data ->
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .liquidGlass(
                    shape = capsuleShape,
                    elevated = true,
                )
                .padding(start = 18.dp, end = 10.dp, top = 11.dp, bottom = 11.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = data.visuals.message,
                style = VdpiTextStyles.body,
                color = palette.inkPrimary,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier
                    .weight(1f)
                    .padding(end = 8.dp),
            )
            data.visuals.actionLabel?.let { action ->
                val actionInteraction = remember { MutableInteractionSource() }
                val actionPressed by actionInteraction.collectIsPressedAsState()
                val actionWash by animateColorAsState(
                    targetValue = if (actionPressed) {
                        palette.accent.copy(alpha = 0.14f)
                    } else {
                        Color.Transparent
                    },
                    animationSpec = tween(durationMillis = if (actionPressed) 60 else 150),
                    label = "snackbarActionWash",
                )
                Box(
                    modifier = Modifier
                        .heightIn(min = 36.dp)
                        .springPress(interactionSource = actionInteraction, pressedScale = 0.96f)
                        .clip(CircleShape)
                        .background(actionWash)
                        .clickable(
                            interactionSource = actionInteraction,
                            indication = null,
                            role = Role.Button,
                        ) { data.performAction() }
                        .padding(horizontal = 12.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = action,
                        fontFamily = GeistSans,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 13.sp,
                        color = palette.accent,
                        maxLines = 1,
                    )
                }
            }
        }
    }
}

/**
 * SF-Symbol-proportioned vector tab icon (22dp default) with clean outlined and
 * filled platform-consistent variants.
 */
@Composable
fun MinimalTabIcon(
    kind: TabIconKind,
    tint: Color,
    modifier: Modifier = Modifier,
    filled: Boolean = false,
) {
    Canvas(modifier = modifier.size(22.dp)) {
        val w = size.width
        val h = size.height
        val strokeWidth = 1.75.dp.toPx()
        val stroke = Stroke(width = strokeWidth, cap = StrokeCap.Round, join = StrokeJoin.Round)

        when (kind) {
            TabIconKind.TUNNEL -> {
                if (filled) {
                    val armStroke = Stroke(width = 1.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round)
                    val leftArm = Path().apply {
                        moveTo(w * 0.14f, h * 0.18f)
                        lineTo(w * 0.31f, h * 0.18f)
                        lineTo(w * 0.47f, h * 0.70f)
                        lineTo(w * 0.30f, h * 0.70f)
                        close()
                    }
                    val rightArm = Path().apply {
                        moveTo(w * 0.53f, h * 0.70f)
                        lineTo(w * 0.69f, h * 0.18f)
                        lineTo(w * 0.86f, h * 0.18f)
                        lineTo(w * 0.70f, h * 0.70f)
                        close()
                    }
                    drawPath(leftArm, color = tint, style = Fill)
                    drawPath(leftArm, color = tint, style = armStroke)
                    drawPath(rightArm, color = tint, style = Fill)
                    drawPath(rightArm, color = tint, style = armStroke)

                    val barHeight = h * 0.11f
                    drawRoundRect(
                        color = tint,
                        topLeft = Offset(w * 0.28f, h * 0.79f),
                        size = Size(w * 0.44f, barHeight),
                        cornerRadius = CornerRadius(barHeight * 0.5f, barHeight * 0.5f),
                    )
                } else {
                    val left = Path().apply {
                        moveTo(w * 0.17f, h * 0.20f)
                        lineTo(w * 0.42f, h * 0.70f)
                    }
                    val right = Path().apply {
                        moveTo(w * 0.58f, h * 0.70f)
                        lineTo(w * 0.83f, h * 0.20f)
                    }
                    drawPath(left, color = tint, style = stroke)
                    drawPath(right, color = tint, style = stroke)
                    drawLine(
                        color = tint,
                        start = Offset(w * 0.31f, h * 0.84f),
                        end = Offset(w * 0.69f, h * 0.84f),
                        strokeWidth = strokeWidth,
                        cap = StrokeCap.Round,
                    )
                }
            }

            TabIconKind.APPS -> {
                val cell = w * 0.33f
                val corner = CornerRadius(2.8.dp.toPx(), 2.8.dp.toPx())
                val origins = listOf(
                    Offset(w * 0.12f, h * 0.12f),
                    Offset(w * 0.55f, h * 0.12f),
                    Offset(w * 0.12f, h * 0.55f),
                    Offset(w * 0.55f, h * 0.55f),
                )
                if (filled) {
                    origins.forEach { topLeft ->
                        drawRoundRect(
                            color = tint,
                            topLeft = topLeft,
                            size = Size(cell, cell),
                            cornerRadius = corner,
                            style = Fill,
                        )
                    }
                } else {
                    val inset = strokeWidth * 0.5f
                    val innerCell = (cell - strokeWidth).coerceAtLeast(1f)
                    val innerCorner = CornerRadius(
                        (2.8.dp.toPx() - inset * 0.5f).coerceAtLeast(1f),
                        (2.8.dp.toPx() - inset * 0.5f).coerceAtLeast(1f),
                    )
                    origins.forEach { topLeft ->
                        drawRoundRect(
                            color = tint,
                            topLeft = Offset(topLeft.x + inset, topLeft.y + inset),
                            size = Size(innerCell, innerCell),
                            cornerRadius = innerCorner,
                            style = stroke,
                        )
                    }
                }
            }

            TabIconKind.SETTINGS -> {
                val topY = h * 0.32f
                val bottomY = h * 0.68f
                val leftX = w * 0.13f
                val rightX = w * 0.87f
                val topKnobX = w * 0.36f
                val bottomKnobX = w * 0.64f

                if (filled) {
                    val railWidth = 1.9.dp.toPx()
                    val knobR = 3.2.dp.toPx()
                    drawLine(tint, Offset(leftX, topY), Offset(rightX, topY), railWidth, StrokeCap.Round)
                    drawCircle(tint, radius = knobR, center = Offset(topKnobX, topY), style = Fill)
                    drawLine(tint, Offset(leftX, bottomY), Offset(rightX, bottomY), railWidth, StrokeCap.Round)
                    drawCircle(tint, radius = knobR, center = Offset(bottomKnobX, bottomY), style = Fill)
                } else {
                    val knobR = 2.9.dp.toPx()
                    val gap = knobR + strokeWidth * 0.35f
                    if (topKnobX - gap > leftX) {
                        drawLine(tint, Offset(leftX, topY), Offset(topKnobX - gap, topY), strokeWidth, StrokeCap.Round)
                    }
                    if (rightX > topKnobX + gap) {
                        drawLine(tint, Offset(topKnobX + gap, topY), Offset(rightX, topY), strokeWidth, StrokeCap.Round)
                    }
                    drawCircle(tint, radius = knobR, center = Offset(topKnobX, topY), style = stroke)

                    if (bottomKnobX - gap > leftX) {
                        drawLine(tint, Offset(leftX, bottomY), Offset(bottomKnobX - gap, bottomY), strokeWidth, StrokeCap.Round)
                    }
                    if (rightX > bottomKnobX + gap) {
                        drawLine(tint, Offset(bottomKnobX + gap, bottomY), Offset(rightX, bottomY), strokeWidth, StrokeCap.Round)
                    }
                    drawCircle(tint, radius = knobR, center = Offset(bottomKnobX, bottomY), style = stroke)
                }
            }
        }
    }
}

enum class TabIconKind {
    TUNNEL,
    APPS,
    SETTINGS,
}
