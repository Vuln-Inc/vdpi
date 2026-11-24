package com.vulninc.vdpi.ui.chrome

import android.app.UiModeManager
import android.content.Context
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateDpAsState
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
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.detectVerticalDragGestures
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.util.VelocityTracker
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.vulninc.vdpi.ui.components.LocalIncreaseContrast
import com.vulninc.vdpi.ui.components.LocalReduceMotion
import com.vulninc.vdpi.ui.components.MinimalTabIcon
import com.vulninc.vdpi.ui.components.TabIconKind
import com.vulninc.vdpi.ui.components.VdpiMotion
import com.vulninc.vdpi.ui.components.liquidGlass
import com.vulninc.vdpi.ui.components.springPress
import com.vulninc.vdpi.ui.theme.GeistSans
import com.vulninc.vdpi.ui.theme.VdpiTextStyles
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens
import com.vulninc.vdpi.util.formatBytes
import com.vulninc.vdpi.vpn.TunnelPhase
import com.vulninc.vdpi.vpn.TunnelRuntimeSnapshot
import kotlinx.coroutines.flow.StateFlow
import java.util.Locale
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.roundToInt
import kotlin.math.sin

internal enum class MainTab(val label: String, val icon: TabIconKind) {
    TUNNEL("Tunnel", TabIconKind.TUNNEL),
    APPS("Apps", TabIconKind.APPS),
    SETTINGS("Settings", TabIconKind.SETTINGS),
}

// ── Accessibility ──

internal data class ChromeAccessibilityState(
    val reduceMotion: Boolean = false,
    val reduceTransparency: Boolean = false,
    val increaseContrast: Boolean = false,
)

@Composable
internal fun rememberChromeAccessibilityState(): ChromeAccessibilityState {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var state by remember(context) { mutableStateOf(readChromeAccessibilityState(context)) }

    DisposableEffect(lifecycleOwner, context) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                state = readChromeAccessibilityState(context)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
    return state
}

private fun readChromeAccessibilityState(context: Context): ChromeAccessibilityState {
    val reduceMotion = runCatching {
        Settings.Global.getFloat(
            context.contentResolver,
            Settings.Global.ANIMATOR_DURATION_SCALE,
            1f,
        ) <= 0f
    }.getOrDefault(false)

    val powerSave = runCatching {
        context.getSystemService(PowerManager::class.java)?.isPowerSaveMode == true
    }.getOrDefault(false)

    val disableWindowBlurs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        runCatching {
            Settings.Global.getInt(context.contentResolver, "disable_window_blurs", 0) == 1
        }.getOrDefault(false)
    } else {
        false
    }

    val increaseContrast = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
        runCatching {
            val uiModeManager = context.getSystemService(UiModeManager::class.java)
            (uiModeManager?.contrast ?: 0f) >= 0.5f
        }.getOrDefault(false)
    } else {
        false
    }

    return ChromeAccessibilityState(
        reduceMotion = reduceMotion,
        reduceTransparency = powerSave || disableWindowBlurs,
        increaseContrast = increaseContrast,
    )
}

private fun Modifier.chromeGlassSurface(
    reduceTransparency: Boolean,
    increaseContrast: Boolean = false,
    shape: Shape = CircleShape,
): Modifier = composed {
    val palette = VdpiThemeTokens.palette
    val effectiveIncreaseContrast = increaseContrast || LocalIncreaseContrast.current
    if (reduceTransparency) {
        val borderColor = if (effectiveIncreaseContrast) palette.borderStrong else palette.border
        this
            .clip(shape)
            .background(palette.surface)
            .border(width = 1.dp, color = borderColor, shape = shape)
    } else {
        this.liquidGlass(shape = shape, elevated = true)
    }
}

// ── Top Reconnect Popup ──

@Composable
internal fun TopReconnectGlassPopup(
    pendingChangeSummary: String,
    isLandscape: Boolean,
    reduceMotion: Boolean,
    reduceTransparency: Boolean,
    increaseContrast: Boolean,
    onReconnect: () -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val density = LocalDensity.current

    var isReconnecting by remember(pendingChangeSummary) { mutableStateOf(false) }
    var dragOffsetY by remember { mutableFloatStateOf(0f) }
    val animatedDragY by animateFloatAsState(
        targetValue = dragOffsetY,
        animationSpec = if (reduceMotion) tween(150) else spring(dampingRatio = 0.82f, stiffness = 420f),
        label = "reconnectPopupDrag",
    )

    val dismissDistancePx = with(density) { -24.dp.toPx() }
    val dismissVelocityPxPerSec = with(density) { -400.dp.toPx() }
    val maxUpDragPx = with(density) { -56.dp.toPx() }
    val maxDownDragPx = with(density) { 12.dp.toPx() }

    val reconnectInteraction = remember { MutableInteractionSource() }
    val dismissInteraction = remember { MutableInteractionSource() }
    val currentOnDismiss by rememberUpdatedState(onDismiss)

    Box(
        modifier = modifier
            .windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal))
            .widthIn(max = if (isLandscape) 460.dp else 520.dp)
            .fillMaxWidth()
            .heightIn(min = if (isLandscape) 48.dp else 56.dp)
            .semantics {
                customActions = listOf(
                    CustomAccessibilityAction(label = "Dismiss") {
                        currentOnDismiss()
                        true
                    },
                )
            }
            .pointerInput(dismissDistancePx, dismissVelocityPxPerSec) {
                val velocityTracker = VelocityTracker()
                var totalDrag = 0f
                var dismissed = false
                detectVerticalDragGestures(
                    onDragStart = {
                        velocityTracker.resetTracking()
                        totalDrag = 0f
                        dismissed = false
                    },
                    onDragEnd = {
                        val velocityY = velocityTracker.calculateVelocity().y
                        if (!dismissed && (totalDrag <= dismissDistancePx || velocityY <= dismissVelocityPxPerSec)) {
                            dismissed = true
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            currentOnDismiss()
                        }
                        dragOffsetY = 0f
                    },
                    onDragCancel = {
                        dragOffsetY = 0f
                    },
                    onVerticalDrag = { change, dragAmount ->
                        change.consume()
                        totalDrag += dragAmount
                        velocityTracker.addPosition(change.uptimeMillis, Offset(0f, totalDrag))
                        dragOffsetY = if (totalDrag < 0f) {
                            totalDrag.coerceAtLeast(maxUpDragPx)
                        } else {
                            (totalDrag * 0.25f).coerceAtMost(maxDownDragPx)
                        }
                    },
                )
            }
            .offset { IntOffset(0, animatedDragY.roundToInt()) }
            .chromeGlassSurface(
                reduceTransparency = reduceTransparency,
                increaseContrast = increaseContrast,
                shape = CircleShape,
            ),
        contentAlignment = Alignment.Center,
    ) {
        val verticalPadding = if (isLandscape) 2.dp else 6.dp
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 14.dp, end = 2.dp, top = verticalPadding, bottom = verticalPadding),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(palette.warning),
            )

            Spacer(Modifier.width(10.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Settings Changed",
                    fontFamily = GeistSans,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 14.sp,
                    lineHeight = 18.sp,
                    color = palette.inkPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = if (pendingChangeSummary.isNotBlank()) {
                        "Reconnect to apply · $pendingChangeSummary"
                    } else {
                        "Reconnect to apply"
                    },
                    fontFamily = GeistSans,
                    fontWeight = FontWeight.Normal,
                    fontSize = 12.sp,
                    lineHeight = 16.sp,
                    color = palette.inkPrimary.copy(alpha = 0.65f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Spacer(Modifier.width(10.dp))

            Box(
                modifier = Modifier
                    .heightIn(min = 44.dp)
                    .clickable(
                        interactionSource = reconnectInteraction,
                        indication = null,
                        enabled = !isReconnecting,
                        role = Role.Button,
                    ) {
                        isReconnecting = true
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        onReconnect()
                    },
                contentAlignment = Alignment.Center,
            ) {
                Box(
                    modifier = Modifier
                        .heightIn(min = 34.dp)
                        .then(
                            if (reduceMotion) {
                                Modifier
                            } else {
                                Modifier.springPress(interactionSource = reconnectInteraction, pressedScale = 0.95f)
                            },
                        )
                        .clip(CircleShape)
                        .background(palette.primaryButtonBg)
                        .padding(horizontal = 14.dp, vertical = 6.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = "Reconnect",
                        fontFamily = GeistSans,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 13.sp,
                        lineHeight = 16.sp,
                        color = palette.primaryButtonInk,
                        maxLines = 1,
                        modifier = Modifier.alpha(if (isReconnecting) 0f else 1f),
                    )
                    if (isReconnecting) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(14.dp),
                            color = palette.primaryButtonInk,
                            strokeWidth = 2.dp,
                        )
                    }
                }
            }

            Spacer(Modifier.width(2.dp))

            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clickable(
                        interactionSource = dismissInteraction,
                        indication = null,
                        role = Role.Button,
                    ) {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onDismiss()
                    }
                    .semantics { contentDescription = "Dismiss" },
                contentAlignment = Alignment.Center,
            ) {
                Box(
                    modifier = Modifier
                        .size(28.dp)
                        .then(
                            if (reduceMotion) {
                                Modifier
                            } else {
                                Modifier.springPress(interactionSource = dismissInteraction, pressedScale = 0.90f)
                            },
                        )
                        .clip(CircleShape)
                        .background(palette.inkPrimary.copy(alpha = 0.08f)),
                    contentAlignment = Alignment.Center,
                ) {
                    CloseGlyph(
                        tint = palette.inkPrimary.copy(alpha = 0.60f),
                        modifier = Modifier.size(11.dp),
                    )
                }
            }
        }
    }
}

// ── Live Accessory Pill ──

@Composable
internal fun FloatingLiveTunnelAccessoryPill(
    tunnelState: StateFlow<TunnelRuntimeSnapshot>,
    isLandscape: Boolean,
    reduceMotion: Boolean,
    reduceTransparency: Boolean,
    increaseContrast: Boolean,
    onOpenTunnel: () -> Unit,
    onDisconnect: () -> Unit,
    onReconnect: () -> Unit,
    modifier: Modifier = Modifier,
) {
    // Scoped locally so 1Hz telemetry ticks never recompose MainActivity, AppsScreen, or SettingsScreen.
    val runtime by tunnelState.collectAsStateWithLifecycle()
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val pillInteraction = remember { MutableInteractionSource() }
    val actionInteraction = remember { MutableInteractionSource() }

    val phase = runtime.phase
    val isError = phase == TunnelPhase.ERROR
    val snap = runtime.telemetry

    val dotColor by animateColorAsState(
        targetValue = when (phase) {
            TunnelPhase.CONNECTED -> palette.signal
            TunnelPhase.CONNECTING -> palette.warning
            TunnelPhase.ERROR -> palette.danger
            TunnelPhase.DISCONNECTED -> palette.inkMuted
        },
        animationSpec = tween(if (reduceMotion) 150 else 200),
        label = "accessoryPillDot",
    )

    val title = when (phase) {
        TunnelPhase.CONNECTED -> "Connected"
        TunnelPhase.CONNECTING -> "Connecting..."
        TunnelPhase.ERROR -> "Tunnel Error"
        TunnelPhase.DISCONNECTED -> "Disconnected"
    }

    val nonConnectedMetric = when (phase) {
        TunnelPhase.CONNECTED -> ""
        TunnelPhase.CONNECTING -> "Establishing tunnel"
        TunnelPhase.ERROR -> runtime.errorMessage?.takeIf { it.isNotBlank() } ?: "Connection interrupted"
        TunnelPhase.DISCONNECTED -> "Tap to open tunnel"
    }

    val metricStyle = remember {
        TextStyle(
            fontFamily = GeistSans,
            fontWeight = FontWeight.Normal,
            fontSize = 12.sp,
            lineHeight = 16.sp,
            fontFeatureSettings = "tnum",
        )
    }
    val metricColor = palette.inkPrimary.copy(alpha = 0.65f)

    val pillMinHeight = if (isLandscape) 44.dp else 50.dp
    val pillVerticalPadding = if (isLandscape) 4.dp else 6.dp

    Box(
        modifier = modifier
            .windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal))
            .widthIn(max = if (isLandscape) 360.dp else 420.dp)
            .fillMaxWidth()
            .heightIn(min = pillMinHeight)
            .chromeGlassSurface(
                reduceTransparency = reduceTransparency,
                increaseContrast = increaseContrast,
                shape = CircleShape,
            ),
        contentAlignment = Alignment.Center,
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(
                modifier = Modifier
                    .weight(1f)
                    .heightIn(min = pillMinHeight)
                    .clickable(
                        interactionSource = pillInteraction,
                        indication = null,
                        role = Role.Button,
                    ) {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onOpenTunnel()
                    }
                    .padding(start = 14.dp, end = 6.dp, top = pillVerticalPadding, bottom = pillVerticalPadding),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                CalmStatusDot(
                    color = dotColor,
                    breathing = phase == TunnelPhase.CONNECTING && !reduceMotion,
                )

                Spacer(Modifier.width(10.dp))

                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.Center,
                ) {
                    Text(
                        text = title,
                        fontFamily = GeistSans,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 13.sp,
                        lineHeight = 17.sp,
                        color = palette.inkPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    if (phase == TunnelPhase.CONNECTED) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = "${formatCompactUptime(snap.uptimeSecs)} · ",
                                style = metricStyle,
                                color = metricColor,
                                maxLines = 1,
                                softWrap = false,
                            )
                            DownArrowGlyph(
                                tint = metricColor,
                                modifier = Modifier.size(10.dp),
                            )
                            Spacer(Modifier.width(3.dp))
                            Text(
                                text = formatBytes(snap.bytesRx),
                                style = metricStyle,
                                color = metricColor,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    } else {
                        Text(
                            text = nonConnectedMetric,
                            style = metricStyle,
                            color = metricColor,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }

            Box(
                modifier = Modifier
                    .padding(end = 3.dp)
                    .size(44.dp)
                    .clickable(
                        interactionSource = actionInteraction,
                        indication = null,
                        role = Role.Button,
                    ) {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        if (isError) {
                            onReconnect()
                        } else {
                            onDisconnect()
                        }
                    }
                    .semantics {
                        contentDescription = if (isError) "Reconnect tunnel" else "Disconnect tunnel"
                    },
                contentAlignment = Alignment.Center,
            ) {
                val buttonFill = if (palette.isDark) {
                    Color.White.copy(alpha = 0.12f)
                } else {
                    palette.inkPrimary.copy(alpha = 0.10f)
                }
                Box(
                    modifier = Modifier
                        .size(34.dp)
                        .then(
                            if (reduceMotion) {
                                Modifier
                            } else {
                                Modifier.springPress(interactionSource = actionInteraction, pressedScale = 0.92f)
                            },
                        )
                        .clip(CircleShape)
                        .background(buttonFill),
                    contentAlignment = Alignment.Center,
                ) {
                    if (isError) {
                        RefreshGlyph(
                            tint = palette.inkPrimary,
                            modifier = Modifier.size(15.dp),
                        )
                    } else {
                        PowerGlyph(
                            tint = palette.inkPrimary,
                            modifier = Modifier.size(15.dp),
                        )
                    }
                }
            }
        }
    }
}

private fun formatCompactUptime(totalSecs: Long): String {
    val safe = totalSecs.coerceAtLeast(0L)
    val h = safe / 3600L
    val m = (safe % 3600L) / 60L
    val s = safe % 60L
    return if (h > 0L) {
        String.format(Locale.US, "%d:%02d:%02d", h, m, s)
    } else {
        String.format(Locale.US, "%02d:%02d", m, s)
    }
}

// ── Floating Tab Bar ──

@Composable
internal fun FloatingLiquidGlassTabBar(
    activeTab: MainTab,
    tunnelPhase: TunnelPhase,
    pendingReconnect: Boolean,
    isLandscape: Boolean,
    reduceMotion: Boolean,
    reduceTransparency: Boolean,
    increaseContrast: Boolean,
    onSelect: (MainTab) -> Unit,
    modifier: Modifier = Modifier,
    showSettingsBadge: Boolean = false,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val density = LocalDensity.current
    val isRtl = LocalLayoutDirection.current == LayoutDirection.Rtl
    val effectiveReduceMotion = reduceMotion || LocalReduceMotion.current
    val tabs = MainTab.entries
    val selectedIndex = tabs.indexOf(activeTab).coerceAtLeast(0)

    val strongLensBorder = increaseContrast || reduceTransparency
    val lensTopColor = when {
        reduceTransparency -> palette.surfaceRaised
        palette.isDark -> Color.White.copy(alpha = 0.16f)
        else -> Color.White.copy(alpha = 0.92f)
    }
    val lensBottomColor = when {
        reduceTransparency -> palette.surfaceRaised
        palette.isDark -> Color.White.copy(alpha = 0.07f)
        else -> Color.White.copy(alpha = 0.78f)
    }
    val lensBorderWidth = if (strongLensBorder) 1.dp else 0.5.dp
    val lensRimColor = when {
        strongLensBorder -> palette.borderStrong
        palette.isDark -> Color.White.copy(alpha = 0.28f)
        else -> Color.Black.copy(alpha = 0.07f)
    }
    val lensShadowColor = Color.Black.copy(alpha = if (palette.isDark) 0.16f else 0.09f)

    val currentActiveTab by rememberUpdatedState(activeTab)
    val currentOnSelect by rememberUpdatedState(onSelect)

    Box(
        modifier = modifier
            .windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal))
            .widthIn(max = if (isLandscape) 360.dp else 420.dp)
            .fillMaxWidth()
            .height(if (isLandscape) 50.dp else 62.dp)
            .chromeGlassSurface(
                reduceTransparency = reduceTransparency,
                increaseContrast = increaseContrast,
                shape = CircleShape,
            ),
        contentAlignment = Alignment.Center,
    ) {
        BoxWithConstraints(
            modifier = Modifier
                .fillMaxSize()
                .padding(if (isLandscape) 3.dp else 4.dp),
        ) {
            val tabWidth = maxWidth / tabs.size
            val tabHeight = maxHeight
            val tabWidthPx = with(density) { tabWidth.toPx() }
            val maxLensOffsetPx = (tabWidthPx * (tabs.size - 1)).coerceAtLeast(0f)

            var dragLensOffsetPx by remember { mutableFloatStateOf(Float.NaN) }
            val isDragging = !dragLensOffsetPx.isNaN()
            val targetOffset = tabWidth * selectedIndex
            val animatedLensOffset by animateDpAsState(
                targetValue = targetOffset,
                animationSpec = if (effectiveReduceMotion) tween(150) else VdpiMotion.tabLensSpring,
                label = "tabLensOffset",
            )
            val effectiveLensOffset = if (isDragging) {
                with(density) { dragLensOffsetPx.toDp() }
            } else {
                animatedLensOffset
            }

            val dragScaleX by animateFloatAsState(
                targetValue = if (isDragging && !effectiveReduceMotion) 1.07f else 1f,
                animationSpec = spring(dampingRatio = 0.72f, stiffness = 420f),
                label = "tabLensDragScaleX",
            )
            val dragScaleY by animateFloatAsState(
                targetValue = if (isDragging && !effectiveReduceMotion) 1.05f else 1f,
                animationSpec = spring(dampingRatio = 0.72f, stiffness = 420f),
                label = "tabLensDragScaleY",
            )

            val travelFraction = if (!effectiveReduceMotion && !isDragging && tabWidth.value > 0f) {
                (abs(animatedLensOffset.value - targetOffset.value) / tabWidth.value).coerceIn(0f, 1f)
            } else {
                0f
            }
            val lensStretchX = dragScaleX * (1f + travelFraction * 0.06f)
            val lensSquashY = dragScaleY * (1f - travelFraction * 0.02f)

            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .pointerInput(tabs.size, tabWidthPx, isRtl) {
                        if (tabWidthPx <= 0f) return@pointerInput
                        detectHorizontalDragGestures(
                            onDragStart = { startOffset ->
                                val rawOffset = startOffset.x - tabWidthPx * 0.5f
                                dragLensOffsetPx = (if (isRtl) maxLensOffsetPx - rawOffset else rawOffset)
                                    .coerceIn(0f, maxLensOffsetPx)
                            },
                            onDragEnd = {
                                dragLensOffsetPx = Float.NaN
                            },
                            onDragCancel = {
                                dragLensOffsetPx = Float.NaN
                            },
                            onHorizontalDrag = { change, _ ->
                                change.consume()
                                val x = change.position.x
                                val rawOffset = x - tabWidthPx * 0.5f
                                dragLensOffsetPx = (if (isRtl) maxLensOffsetPx - rawOffset else rawOffset)
                                    .coerceIn(0f, maxLensOffsetPx)
                                val rawIdx = (x / tabWidthPx).toInt().coerceIn(0, tabs.lastIndex)
                                val hoveredIdx = if (isRtl) tabs.lastIndex - rawIdx else rawIdx
                                val hoveredTab = tabs[hoveredIdx]
                                if (hoveredTab != currentActiveTab) {
                                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    currentOnSelect(hoveredTab)
                                }
                            },
                        )
                    },
            ) {
                // Sliding active tab indicator
                val lensShadowModifier = if (reduceTransparency) {
                    Modifier
                } else {
                    Modifier.shadow(
                        elevation = if (palette.isDark) 3.dp else 4.dp,
                        shape = CircleShape,
                        clip = false,
                        ambientColor = lensShadowColor,
                        spotColor = lensShadowColor,
                    )
                }

                Box(
                    modifier = Modifier
                        .offset { IntOffset(effectiveLensOffset.roundToPx(), 0) }
                        .width(tabWidth)
                        .height(tabHeight)
                        .graphicsLayer {
                            scaleX = lensStretchX
                            scaleY = lensSquashY
                        }
                        .then(lensShadowModifier)
                        .clip(CircleShape)
                        .drawWithContent {
                            if (reduceTransparency) {
                                drawRect(color = palette.surfaceRaised)
                            } else if (size.height > 0f) {
                                drawRect(
                                    brush = Brush.verticalGradient(
                                        colorStops = arrayOf(
                                            0.00f to lensTopColor,
                                            1.00f to lensBottomColor,
                                        ),
                                        startY = 0f,
                                        endY = size.height,
                                    ),
                                )
                                drawRect(
                                    brush = Brush.verticalGradient(
                                        colorStops = arrayOf(
                                            0.00f to Color.White.copy(alpha = if (palette.isDark) 0.14f else 0.65f),
                                            0.28f to Color.Transparent,
                                            1.00f to Color.White.copy(alpha = if (palette.isDark) 0.04f else 0.18f),
                                        ),
                                        startY = 0f,
                                        endY = size.height,
                                    ),
                                )
                            }
                            drawContent()
                        }
                        .border(width = lensBorderWidth, color = lensRimColor, shape = CircleShape),
                )

                Row(
                    modifier = Modifier.fillMaxSize(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    tabs.forEach { tab ->
                        val statusDotColor = when {
                            tab == MainTab.TUNNEL && tunnelPhase == TunnelPhase.CONNECTED ->
                                if (pendingReconnect) palette.warning else palette.signal
                            tab == MainTab.SETTINGS && showSettingsBadge ->
                                palette.accent
                            else -> null
                        }
                        FloatingTabBarItem(
                            tab = tab,
                            selected = tab == activeTab,
                            statusDotColor = statusDotColor,
                            isLandscape = isLandscape,
                            reduceMotion = effectiveReduceMotion,
                            onSelect = {
                                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                onSelect(tab)
                            },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun RowScope.FloatingTabBarItem(
    tab: MainTab,
    selected: Boolean,
    statusDotColor: Color?,
    isLandscape: Boolean,
    reduceMotion: Boolean,
    onSelect: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val interactionSource = remember { MutableInteractionSource() }
    val tint by animateColorAsState(
        targetValue = if (selected) palette.accent else palette.inkSecondary,
        animationSpec = tween(if (reduceMotion) 150 else 180),
        label = "tabTint",
    )
    val iconScale by animateFloatAsState(
        targetValue = if (selected && !reduceMotion) 1.04f else 1f,
        animationSpec = spring(dampingRatio = 0.78f, stiffness = 460f),
        label = "tabIconScale",
    )

    Box(
        modifier = Modifier
            .weight(1f)
            .fillMaxHeight()
            .clip(CircleShape)
            .then(
                if (reduceMotion) {
                    Modifier
                } else {
                    Modifier.springPress(interactionSource = interactionSource, pressedScale = 0.95f)
                },
            )
            .selectable(
                selected = selected,
                interactionSource = interactionSource,
                indication = null,
                role = Role.Tab,
                onClick = {
                    if (!selected) {
                        onSelect()
                    }
                },
            ),
        contentAlignment = Alignment.Center,
    ) {
        if (isLandscape) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    MinimalTabIcon(
                        kind = tab.icon,
                        tint = tint,
                        filled = selected,
                        modifier = Modifier
                            .size(18.dp)
                            .graphicsLayer {
                                scaleX = iconScale
                                scaleY = iconScale
                            },
                    )
                    if (statusDotColor != null) {
                        Box(
                            modifier = Modifier
                                .align(Alignment.TopEnd)
                                .offset(x = 4.dp, y = (-2).dp)
                                .size(6.dp)
                                .clip(CircleShape)
                                .background(statusDotColor),
                        )
                    }
                }
                Text(
                    text = tab.label,
                    style = VdpiTextStyles.tabLabel.copy(
                        fontSize = 12.sp,
                        fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium,
                    ),
                    color = tint,
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(horizontal = 4.dp),
                )
            }
        } else {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Box(contentAlignment = Alignment.Center) {
                    MinimalTabIcon(
                        kind = tab.icon,
                        tint = tint,
                        filled = selected,
                        modifier = Modifier.graphicsLayer {
                            scaleX = iconScale
                            scaleY = iconScale
                        },
                    )
                    if (statusDotColor != null) {
                        Box(
                            modifier = Modifier
                                .align(Alignment.TopEnd)
                                .offset(x = 6.dp, y = (-3).dp)
                                .size(6.dp)
                                .clip(CircleShape)
                                .background(statusDotColor),
                        )
                    }
                }
                Spacer(Modifier.height(2.dp))
                Text(
                    text = tab.label,
                    style = VdpiTextStyles.tabLabel.copy(
                        fontSize = 11.sp,
                        fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium,
                    ),
                    color = tint,
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(horizontal = 4.dp),
                )
            }
        }
    }
}

// ── Chrome Glyphs ──

@Composable
private fun CalmStatusDot(
    color: Color,
    breathing: Boolean,
    modifier: Modifier = Modifier,
) {
    val dotAlpha = if (breathing) {
        val infinite = rememberInfiniteTransition(label = "calmStatusDotBreathe")
        val animated by infinite.animateFloat(
            initialValue = 1f,
            targetValue = 0.45f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 1200, easing = FastOutSlowInEasing),
                repeatMode = RepeatMode.Reverse,
            ),
            label = "calmStatusDotAlpha",
        )
        animated
    } else {
        1f
    }

    Box(
        modifier = modifier
            .size(8.dp)
            .graphicsLayer { alpha = dotAlpha }
            .clip(CircleShape)
            .background(color),
    )
}

@Composable
private fun CloseGlyph(
    tint: Color,
    modifier: Modifier = Modifier,
) {
    Canvas(modifier = modifier) {
        val stroke = 1.75.dp.toPx()
        drawLine(
            color = tint,
            start = Offset(0f, 0f),
            end = Offset(size.width, size.height),
            strokeWidth = stroke,
            cap = StrokeCap.Round,
        )
        drawLine(
            color = tint,
            start = Offset(size.width, 0f),
            end = Offset(0f, size.height),
            strokeWidth = stroke,
            cap = StrokeCap.Round,
        )
    }
}

@Composable
private fun DownArrowGlyph(
    tint: Color,
    modifier: Modifier = Modifier,
) {
    val headPath = remember { Path() }
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        val strokeWidth = 1.4.dp.toPx()
        val stroke = Stroke(width = strokeWidth, cap = StrokeCap.Round, join = StrokeJoin.Round)
        drawLine(
            color = tint,
            start = Offset(w * 0.50f, h * 0.14f),
            end = Offset(w * 0.50f, h * 0.84f),
            strokeWidth = strokeWidth,
            cap = StrokeCap.Round,
        )
        headPath.reset()
        headPath.moveTo(w * 0.22f, h * 0.56f)
        headPath.lineTo(w * 0.50f, h * 0.84f)
        headPath.lineTo(w * 0.78f, h * 0.56f)
        drawPath(path = headPath, color = tint, style = stroke)
    }
}

@Composable
private fun RefreshGlyph(
    tint: Color,
    modifier: Modifier = Modifier,
) {
    val arrowPath = remember { Path() }
    Canvas(modifier = modifier) {
        val strokeWidth = 1.75.dp.toPx()
        val cx = size.width * 0.5f
        val cy = size.height * 0.5f
        val radius = ((minOf(size.width, size.height) - strokeWidth * 2f) * 0.44f).coerceAtLeast(1f)
        val stroke = Stroke(width = strokeWidth, cap = StrokeCap.Round, join = StrokeJoin.Round)

        drawArc(
            color = tint,
            startAngle = 30f,
            sweepAngle = 295f,
            useCenter = false,
            topLeft = Offset(cx - radius, cy - radius),
            size = Size(radius * 2f, radius * 2f),
            style = stroke,
        )

        val tipAngle = -35.0 * PI / 180.0
        val tx = cx + (radius * cos(tipAngle)).toFloat()
        val ty = cy + (radius * sin(tipAngle)).toFloat()
        val backAngle = tipAngle + PI * 1.5
        val barbSpread = 42.0 * PI / 180.0
        val barbLen = radius * 0.46f

        val b1x = tx + (barbLen * cos(backAngle - barbSpread)).toFloat()
        val b1y = ty + (barbLen * sin(backAngle - barbSpread)).toFloat()
        val b2x = tx + (barbLen * cos(backAngle + barbSpread)).toFloat()
        val b2y = ty + (barbLen * sin(backAngle + barbSpread)).toFloat()

        arrowPath.reset()
        arrowPath.moveTo(b1x, b1y)
        arrowPath.lineTo(tx, ty)
        arrowPath.lineTo(b2x, b2y)
        drawPath(path = arrowPath, color = tint, style = stroke)
    }
}

@Composable
private fun PowerGlyph(
    tint: Color,
    modifier: Modifier = Modifier,
) {
    Canvas(modifier = modifier) {
        val strokeWidth = 1.75.dp.toPx()
        val inset = strokeWidth * 0.7f
        val arcSize = Size(
            width = (size.width - inset * 2f).coerceAtLeast(1f),
            height = (size.height - inset * 2f).coerceAtLeast(1f),
        )
        drawArc(
            color = tint,
            startAngle = -52f,
            sweepAngle = 284f,
            useCenter = false,
            topLeft = Offset(inset, inset),
            size = arcSize,
            style = Stroke(width = strokeWidth, cap = StrokeCap.Round),
        )
        drawLine(
            color = tint,
            start = Offset(size.width * 0.5f, inset * 0.45f),
            end = Offset(size.width * 0.5f, size.height * 0.48f),
            strokeWidth = strokeWidth,
            cap = StrokeCap.Round,
        )
    }
}
