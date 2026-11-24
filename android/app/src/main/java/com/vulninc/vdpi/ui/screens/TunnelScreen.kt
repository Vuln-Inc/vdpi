package com.vulninc.vdpi.ui.screens

import android.content.res.Configuration
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.vulninc.vdpi.BuildConfig
import com.vulninc.vdpi.data.SplitTunnelMode
import com.vulninc.vdpi.data.VdpiSettings
import com.vulninc.vdpi.engine.TelemetrySnapshot
import com.vulninc.vdpi.ui.DoctorUiState
import com.vulninc.vdpi.ui.components.FloatingGlassIconButton
import com.vulninc.vdpi.ui.components.HairlineRule
import com.vulninc.vdpi.ui.components.InsetGroupedCard
import com.vulninc.vdpi.ui.components.InsetGroupedRow
import com.vulninc.vdpi.ui.components.LocalBottomChromePadding
import com.vulninc.vdpi.ui.components.LocalReduceMotion
import com.vulninc.vdpi.ui.components.LocalTopOverlayPadding
import com.vulninc.vdpi.ui.components.SectionOverline
import com.vulninc.vdpi.ui.components.springPress
import com.vulninc.vdpi.ui.theme.GeistSans
import com.vulninc.vdpi.ui.theme.VdpiTextStyles
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens
import com.vulninc.vdpi.util.formatBytes
import com.vulninc.vdpi.util.formatStageLabel
import com.vulninc.vdpi.util.formatUptime
import com.vulninc.vdpi.vpn.TunnelPhase
import com.vulninc.vdpi.vpn.TunnelRuntimeSnapshot
import kotlinx.coroutines.flow.StateFlow
import java.util.Locale

// ── Tunnel Dashboard Screen ──

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TunnelScreen(
    tunnelState: StateFlow<TunnelRuntimeSnapshot>,
    settings: VdpiSettings,
    doctorState: DoctorUiState,
    @Suppress("UNUSED_PARAMETER") engineVersion: String = BuildConfig.VERSION_NAME,
    pendingReconnect: Boolean,
    onToggleTunnel: () -> Unit,
    onReconnect: () -> Unit,
    onRunDoctor: () -> Unit,
    modifier: Modifier = Modifier,
) {
    // Scoped locally so 1Hz telemetry updates never recompose MainActivity, Apps, or Settings.
    val runtime by tunnelState.collectAsStateWithLifecycle()
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val reduceMotion = LocalReduceMotion.current

    var showDoctorSheet by remember { mutableStateOf(false) }
    var showLogSheet by remember { mutableStateOf(false) }
    var lastSeenAlertSeq by rememberSaveable { mutableLongStateOf(-1L) }

    val isConnected = runtime.phase == TunnelPhase.CONNECTED

    val doctorBadgeColor: Color? = when {
        doctorState.running -> palette.warning
        doctorState.report != null && (!doctorState.report.ok || doctorState.report.checks.any { !it.passed }) ->
            palette.danger
        else -> null
    }

    val latestAlertSeq = runtime.telemetry.events
        .lastOrNull { isAlertLogLevel(it.level) }
        ?.seq ?: -1L
    val maxEventSeq = runtime.telemetry.events.maxOfOrNull { it.seq } ?: -1L

    LaunchedEffect(maxEventSeq) {
        if (maxEventSeq < lastSeenAlertSeq) {
            lastSeenAlertSeq = -1L
        }
    }

    LaunchedEffect(showLogSheet, latestAlertSeq) {
        if (showLogSheet && latestAlertSeq > lastSeenAlertSeq) {
            lastSeenAlertSeq = maxOf(lastSeenAlertSeq, latestAlertSeq)
        }
    }

    val hasLogAlert = latestAlertSeq > lastSeenAlertSeq

    val openDiagnostics: () -> Unit = {
        showLogSheet = false
        showDoctorSheet = true
        if (doctorState.report == null && !doctorState.running) {
            onRunDoctor()
        }
    }

    val openLogs: () -> Unit = {
        showDoctorSheet = false
        showLogSheet = true
        lastSeenAlertSeq = maxOf(lastSeenAlertSeq, latestAlertSeq)
    }

    val toggleTunnelWithHaptic: () -> Unit = {
        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
        onToggleTunnel()
    }

    val reconnectWithHaptic: () -> Unit = {
        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
        onReconnect()
    }

    val configuration = LocalConfiguration.current
    val isLandscape = configuration.orientation == Configuration.ORIENTATION_LANDSCAPE &&
        configuration.screenWidthDp >= 560
    val topOverlayPadding = LocalTopOverlayPadding.current
    val bottomChromePadding = LocalBottomChromePadding.current

    if (isLandscape) {
        LandscapeTunnelLayout(
            runtime = runtime,
            settings = settings,
            isConnected = isConnected,
            pendingReconnect = pendingReconnect,
            reduceMotion = reduceMotion,
            doctorBadgeColor = doctorBadgeColor,
            hasLogAlert = hasLogAlert,
            topOverlayPadding = topOverlayPadding,
            bottomChromePadding = bottomChromePadding,
            onOpenDiagnostics = openDiagnostics,
            onOpenLogs = openLogs,
            onToggleTunnel = toggleTunnelWithHaptic,
            onReconnect = reconnectWithHaptic,
            modifier = modifier,
        )
    } else {
        PortraitTunnelLayout(
            runtime = runtime,
            settings = settings,
            isConnected = isConnected,
            pendingReconnect = pendingReconnect,
            reduceMotion = reduceMotion,
            doctorBadgeColor = doctorBadgeColor,
            hasLogAlert = hasLogAlert,
            topOverlayPadding = topOverlayPadding,
            bottomChromePadding = bottomChromePadding,
            onOpenDiagnostics = openDiagnostics,
            onOpenLogs = openLogs,
            onToggleTunnel = toggleTunnelWithHaptic,
            onReconnect = reconnectWithHaptic,
            modifier = modifier,
        )
    }

    val sheetContainerColor = if (palette.isDark) palette.surface else palette.canvas

    if (showDoctorSheet) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(
            onDismissRequest = { showDoctorSheet = false },
            sheetState = sheetState,
            shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
            containerColor = sheetContainerColor,
            contentColor = palette.inkPrimary,
            dragHandle = { SheetGrabber(compact = isLandscape) },
        ) {
            SyncModalSheetSystemBars(isDark = palette.isDark)
            DoctorSheetContent(
                doctorState = doctorState,
                isLandscape = isLandscape,
                onRerun = onRunDoctor,
                onDismiss = { showDoctorSheet = false },
            )
        }
    }

    if (showLogSheet) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(
            onDismissRequest = { showLogSheet = false },
            sheetState = sheetState,
            shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
            containerColor = sheetContainerColor,
            contentColor = palette.inkPrimary,
            dragHandle = { SheetGrabber(compact = isLandscape) },
        ) {
            SyncModalSheetSystemBars(isDark = palette.isDark)
            EngineLogSheetContent(
                events = runtime.telemetry.events,
                isLandscape = isLandscape,
                onDismiss = { showLogSheet = false },
            )
        }
    }
}

// ── Adaptive Dashboard Layouts ──

@Composable
private fun LandscapeTunnelLayout(
    runtime: TunnelRuntimeSnapshot,
    settings: VdpiSettings,
    isConnected: Boolean,
    pendingReconnect: Boolean,
    reduceMotion: Boolean,
    doctorBadgeColor: Color?,
    hasLogAlert: Boolean,
    topOverlayPadding: Dp,
    bottomChromePadding: Dp,
    onOpenDiagnostics: () -> Unit,
    onOpenLogs: () -> Unit,
    onToggleTunnel: () -> Unit,
    onReconnect: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .windowInsetsPadding(
                WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
            ),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(
            modifier = Modifier
                .widthIn(max = 880.dp)
                .fillMaxWidth()
                .padding(horizontal = 20.dp),
        ) {
            Spacer(Modifier.height(topOverlayPadding))

            TunnelHeaderRow(
                compact = true,
                doctorBadgeColor = doctorBadgeColor,
                hasLogAlert = hasLogAlert,
                onOpenDiagnostics = onOpenDiagnostics,
                onOpenLogs = onOpenLogs,
            )

            // Adaptive two-pane landscape dashboard
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp),
                verticalAlignment = Alignment.Top,
            ) {
                // Left pane: Compact Hero Card + inline reconnect banner
                Column(modifier = Modifier.weight(0.46f)) {
                    TunnelHeroCard(
                        runtime = runtime,
                        settings = settings,
                        reduceMotion = reduceMotion,
                        compact = true,
                        onToggleTunnel = onToggleTunnel,
                    )

                    PendingReconnectSection(
                        visible = pendingReconnect && isConnected,
                        reduceMotion = reduceMotion,
                        compact = true,
                        onReconnect = onReconnect,
                    )
                }

                // Right pane: Live Telemetry or Standby Profile beside the Hero Card
                Box(modifier = Modifier.weight(0.54f)) {
                    TunnelDetailsSection(
                        isConnected = isConnected,
                        telemetry = runtime.telemetry,
                        settings = settings,
                        transitionLabel = "tunnelDetailsTransitionLandscape",
                    )
                }
            }

            Spacer(Modifier.height(bottomChromePadding + 8.dp))
        }
    }
}

@Composable
private fun PortraitTunnelLayout(
    runtime: TunnelRuntimeSnapshot,
    settings: VdpiSettings,
    isConnected: Boolean,
    pendingReconnect: Boolean,
    reduceMotion: Boolean,
    doctorBadgeColor: Color?,
    hasLogAlert: Boolean,
    topOverlayPadding: Dp,
    bottomChromePadding: Dp,
    onOpenDiagnostics: () -> Unit,
    onOpenLogs: () -> Unit,
    onToggleTunnel: () -> Unit,
    onReconnect: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .windowInsetsPadding(
                WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
            )
            .padding(horizontal = 16.dp),
    ) {
        Spacer(Modifier.height(topOverlayPadding))
        Spacer(Modifier.height(12.dp))

        TunnelHeaderRow(
            compact = false,
            doctorBadgeColor = doctorBadgeColor,
            hasLogAlert = hasLogAlert,
            onOpenDiagnostics = onOpenDiagnostics,
            onOpenLogs = onOpenLogs,
        )

        Spacer(Modifier.height(16.dp))

        // Serene opaque Apple Hero Card
        TunnelHeroCard(
            runtime = runtime,
            settings = settings,
            reduceMotion = reduceMotion,
            onToggleTunnel = onToggleTunnel,
        )

        // Persistent inline reconnect row when settings changed during an active tunnel
        PendingReconnectSection(
            visible = pendingReconnect && isConnected,
            reduceMotion = reduceMotion,
            compact = false,
            onReconnect = onReconnect,
        )

        Spacer(Modifier.height(24.dp))

        // Inset Grouped Telemetry or Standby Profile
        TunnelDetailsSection(
            isConnected = isConnected,
            telemetry = runtime.telemetry,
            settings = settings,
            transitionLabel = "tunnelDetailsTransition",
        )

        Spacer(Modifier.height(24.dp))
        Spacer(Modifier.height(bottomChromePadding))
    }
}

@Composable
private fun TunnelHeaderRow(
    compact: Boolean,
    doctorBadgeColor: Color?,
    hasLogAlert: Boolean,
    onOpenDiagnostics: () -> Unit,
    onOpenLogs: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val buttonSize = if (compact) 38.dp else 42.dp
    val titleStyle = if (compact) {
        VdpiTextStyles.pageTitle.copy(
            fontSize = 24.sp,
            lineHeight = 28.sp,
            letterSpacing = (-0.3).sp,
        )
    } else {
        VdpiTextStyles.pageTitle
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .then(if (compact) Modifier.padding(top = 6.dp, bottom = 10.dp) else Modifier),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = "vdpi",
            style = titleStyle,
            color = palette.inkPrimary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f),
        )

        Spacer(Modifier.width(12.dp))

        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FloatingGlassIconButton(
                onClick = onOpenDiagnostics,
                contentDescription = "Diagnostics",
                size = buttonSize,
                badgeColor = doctorBadgeColor,
            ) {
                DiagnosticsGlyph(tint = palette.inkPrimary)
            }

            FloatingGlassIconButton(
                onClick = onOpenLogs,
                contentDescription = "Engine logs",
                size = buttonSize,
                badgeColor = if (hasLogAlert) palette.danger else null,
            ) {
                EngineLogGlyph(tint = palette.inkPrimary)
            }
        }
    }
}

@Composable
private fun PendingReconnectSection(
    visible: Boolean,
    reduceMotion: Boolean,
    compact: Boolean,
    onReconnect: () -> Unit,
) {
    AnimatedVisibility(
        visible = visible,
        enter = if (reduceMotion) {
            fadeIn(tween(150))
        } else {
            fadeIn(tween(180)) + expandVertically(tween(200))
        },
        exit = if (reduceMotion) {
            fadeOut(tween(120))
        } else {
            fadeOut(tween(140)) + shrinkVertically(tween(160))
        },
    ) {
        Column {
            Spacer(Modifier.height(if (compact) 10.dp else 12.dp))
            InlineReconnectRow(
                compact = compact,
                onReconnect = onReconnect,
            )
        }
    }
}

@Composable
private fun TunnelDetailsSection(
    isConnected: Boolean,
    telemetry: TelemetrySnapshot,
    settings: VdpiSettings,
    transitionLabel: String,
) {
    AnimatedContent(
        targetState = isConnected,
        transitionSpec = {
            fadeIn(tween(180)) togetherWith fadeOut(tween(130))
        },
        label = transitionLabel,
    ) { live ->
        if (live) {
            LiveTelemetrySection(
                telemetry = telemetry,
                settings = settings,
            )
        } else {
            StandbyProfileSection(
                settings = settings,
            )
        }
    }
}

// ── Hero Card ──

@Composable
private fun TunnelHeroCard(
    runtime: TunnelRuntimeSnapshot,
    settings: VdpiSettings,
    reduceMotion: Boolean,
    onToggleTunnel: () -> Unit,
    compact: Boolean = false,
) {
    val palette = VdpiThemeTokens.palette
    val phase = runtime.phase
    val snap = runtime.telemetry
    val isError = phase == TunnelPhase.ERROR

    val discFill by animateColorAsState(
        targetValue = when (phase) {
            TunnelPhase.CONNECTED -> palette.signalTint
            TunnelPhase.CONNECTING -> palette.warningTint
            TunnelPhase.ERROR -> palette.dangerTint
            TunnelPhase.DISCONNECTED -> palette.surfaceRaised
        },
        animationSpec = tween(220),
        label = "heroDiscFill",
    )
    val glyphTint by animateColorAsState(
        targetValue = when (phase) {
            TunnelPhase.CONNECTED -> palette.signal
            TunnelPhase.CONNECTING -> palette.warning
            TunnelPhase.ERROR -> palette.danger
            TunnelPhase.DISCONNECTED -> palette.inkSecondary
        },
        animationSpec = tween(220),
        label = "heroGlyphTint",
    )

    val discAlpha = if (phase == TunnelPhase.CONNECTING && !reduceMotion) {
        val infinite = rememberInfiniteTransition(label = "connectingPulse")
        val animated by infinite.animateFloat(
            initialValue = 1f,
            targetValue = 0.56f,
            animationSpec = infiniteRepeatable(
                animation = tween(1200, easing = FastOutSlowInEasing),
                repeatMode = RepeatMode.Reverse,
            ),
            label = "connectingPulseAlpha",
        )
        animated
    } else {
        1f
    }

    val statusTitle = when (phase) {
        TunnelPhase.CONNECTED -> "Connected"
        TunnelPhase.CONNECTING -> "Connecting"
        TunnelPhase.DISCONNECTED -> "Not Connected"
        TunnelPhase.ERROR -> "Connection Error"
    }

    val dnsCompact = "${settings.dnsAddr.trim().ifBlank { "1.1.1.1" }} ${if (settings.enableDoh) "DoH" else "UDP"}"
    val subtitle = when (phase) {
        TunnelPhase.CONNECTED -> "$dnsCompact · ${formatHeroUptime(snap.uptimeSecs)}"
        TunnelPhase.CONNECTING -> "Establishing local tunnel..."
        TunnelPhase.DISCONNECTED -> "Local anti-DPI tunnel ready"
        TunnelPhase.ERROR -> runtime.errorMessage?.takeIf { it.isNotBlank() } ?: "Tunnel stopped unexpectedly"
    }

    InsetGroupedCard(
        modifier = Modifier.fillMaxWidth(),
        radius = 16.dp,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(
                    horizontal = if (compact) 16.dp else 20.dp,
                    vertical = if (compact) 14.dp else 22.dp,
                ),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Box(
                modifier = Modifier
                    .size(if (compact) 52.dp else 68.dp)
                    .graphicsLayer { alpha = discAlpha }
                    .clip(CircleShape)
                    .background(discFill),
                contentAlignment = Alignment.Center,
            ) {
                TunnelStatusGlyph(
                    phase = phase,
                    tint = glyphTint,
                    glyphSize = if (compact) 24.dp else 28.dp,
                )
            }

            Spacer(Modifier.height(if (compact) 10.dp else 14.dp))

            AnimatedContent(
                targetState = statusTitle,
                transitionSpec = {
                    fadeIn(tween(180)) togetherWith fadeOut(tween(120))
                },
                label = "heroStatusTitle",
            ) { title ->
                Text(
                    text = title,
                    style = if (compact) {
                        VdpiTextStyles.hero.copy(fontSize = 22.sp, lineHeight = 26.sp)
                    } else {
                        VdpiTextStyles.hero
                    },
                    color = palette.inkPrimary,
                    textAlign = TextAlign.Center,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Spacer(Modifier.height(if (compact) 3.dp else 4.dp))

            Text(
                text = subtitle,
                style = if (compact) {
                    VdpiTextStyles.body.copy(
                        fontSize = 14.sp,
                        lineHeight = 19.sp,
                        fontFeatureSettings = "tnum",
                    )
                } else {
                    VdpiTextStyles.body.copy(fontFeatureSettings = "tnum")
                },
                color = palette.inkSecondary,
                textAlign = TextAlign.Center,
                maxLines = if (isError) 2 else 1,
                overflow = TextOverflow.Ellipsis,
            )

            Spacer(Modifier.height(if (compact) 14.dp else 20.dp))

            PrimaryTunnelActionButton(
                phase = phase,
                onClick = onToggleTunnel,
                compact = compact,
            )
        }
    }
}

@Composable
private fun PrimaryTunnelActionButton(
    phase: TunnelPhase,
    onClick: () -> Unit,
    compact: Boolean = false,
) {
    val palette = VdpiThemeTokens.palette
    val interaction = remember { MutableInteractionSource() }
    val isPressed by interaction.collectIsPressedAsState()
    val isProminent = phase == TunnelPhase.DISCONNECTED || phase == TunnelPhase.ERROR
    val isConnecting = phase == TunnelPhase.CONNECTING

    val containerColor by animateColorAsState(
        targetValue = if (isProminent) palette.primaryButtonBg else palette.surfaceRaised,
        animationSpec = tween(200),
        label = "ctaContainerColor",
    )
    val contentColor by animateColorAsState(
        targetValue = if (isProminent) palette.primaryButtonInk else palette.inkPrimary,
        animationSpec = tween(200),
        label = "ctaContentColor",
    )
    val pressWash by animateColorAsState(
        targetValue = if (isPressed) {
            if (isProminent) Color.Black.copy(alpha = 0.14f) else palette.inkPrimary.copy(alpha = 0.08f)
        } else {
            Color.Transparent
        },
        animationSpec = tween(durationMillis = if (isPressed) 60 else 150),
        label = "ctaPressWash",
    )

    val label = when (phase) {
        TunnelPhase.CONNECTED -> "Disconnect"
        TunnelPhase.CONNECTING -> "Connecting..."
        TunnelPhase.DISCONNECTED, TunnelPhase.ERROR -> "Connect"
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = if (compact) 44.dp else 50.dp)
            .springPress(interactionSource = interaction, pressedScale = 0.98f)
            .clip(CircleShape)
            .background(containerColor)
            .background(pressWash)
            .clickable(
                interactionSource = interaction,
                indication = null,
                role = Role.Button,
                onClick = onClick,
            )
            .padding(
                horizontal = if (compact) 16.dp else 20.dp,
                vertical = if (compact) 10.dp else 12.dp,
            ),
        contentAlignment = Alignment.Center,
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center,
        ) {
            if (isConnecting) {
                CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    strokeWidth = 2.dp,
                    color = palette.inkSecondary,
                )
                Spacer(Modifier.width(10.dp))
            }
            Text(
                text = label,
                style = VdpiTextStyles.button.copy(fontSize = if (compact) 16.sp else 17.sp),
                color = contentColor,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

// ── Inline Reconnect Row ──

@Composable
private fun InlineReconnectRow(
    onReconnect: () -> Unit,
    compact: Boolean = false,
) {
    val palette = VdpiThemeTokens.palette
    val interaction = remember { MutableInteractionSource() }
    val isPressed by interaction.collectIsPressedAsState()
    val pillWash by animateColorAsState(
        targetValue = if (isPressed) Color.Black.copy(alpha = 0.14f) else Color.Transparent,
        animationSpec = tween(durationMillis = if (isPressed) 60 else 150),
        label = "reconnectPillWash",
    )

    InsetGroupedCard(
        modifier = Modifier.fillMaxWidth(),
        radius = 16.dp,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(
                    start = if (compact) 12.dp else 16.dp,
                    end = if (compact) 10.dp else 12.dp,
                    top = if (compact) 10.dp else 12.dp,
                    bottom = if (compact) 10.dp else 12.dp,
                ),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            WarningCircleGlyph(tint = palette.warning)

            Spacer(Modifier.width(if (compact) 10.dp else 12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Settings Changed",
                    style = VdpiTextStyles.body.copy(fontWeight = FontWeight.SemiBold),
                    color = palette.inkPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(Modifier.height(1.dp))
                Text(
                    text = "Reconnect to apply",
                    style = VdpiTextStyles.caption,
                    color = palette.inkSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Spacer(Modifier.width(if (compact) 8.dp else 10.dp))

            Box(
                modifier = Modifier
                    .heightIn(min = 44.dp)
                    .clickable(
                        interactionSource = interaction,
                        indication = null,
                        role = Role.Button,
                        onClick = onReconnect,
                    ),
                contentAlignment = Alignment.Center,
            ) {
                Box(
                    modifier = Modifier
                        .springPress(interactionSource = interaction, pressedScale = 0.96f)
                        .clip(CircleShape)
                        .background(palette.primaryButtonBg)
                        .background(pillWash)
                        .padding(
                            horizontal = if (compact) 12.dp else 14.dp,
                            vertical = if (compact) 7.dp else 8.dp,
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = "Reconnect",
                        fontFamily = GeistSans,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 14.sp,
                        color = palette.primaryButtonInk,
                        maxLines = 1,
                    )
                }
            }
        }
    }
}

// ── Live Telemetry & Standby Profile ──

@Composable
private fun LiveTelemetrySection(
    telemetry: TelemetrySnapshot,
    settings: VdpiSettings,
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        SectionOverline(text = "Connection")

        InsetGroupedCard(
            modifier = Modifier.fillMaxWidth(),
            radius = 16.dp,
        ) {
            InsetGroupedRow(
                title = "Download",
                trailing = { TabularRowValue(text = formatBytes(telemetry.bytesRx)) },
            )
            HairlineRule(startIndent = 16.dp)
            InsetGroupedRow(
                title = "Upload",
                trailing = { TabularRowValue(text = formatBytes(telemetry.bytesTx)) },
            )
            HairlineRule(startIndent = 16.dp)
            InsetGroupedRow(
                title = "Strategy",
                trailing = { TabularRowValue(text = formatStageLabel(telemetry.stageLabel)) },
            )
            HairlineRule(startIndent = 16.dp)
            InsetGroupedRow(
                title = "DNS",
                trailing = { TabularRowValue(text = formatDnsDetail(settings)) },
            )
            HairlineRule(startIndent = 16.dp)
            InsetGroupedRow(
                title = "QUIC Blocked",
                trailing = {
                    TabularRowValue(
                        text = if (settings.blockQuic) telemetry.quicBlocked.toString() else "Allowed",
                    )
                },
            )
        }
    }
}

@Composable
private fun StandbyProfileSection(
    settings: VdpiSettings,
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        SectionOverline(text = "Profile")

        InsetGroupedCard(
            modifier = Modifier.fillMaxWidth(),
            radius = 16.dp,
        ) {
            InsetGroupedRow(
                title = "Mode",
                trailing = { TabularRowValue(text = settings.desyncMode.label) },
            )
            HairlineRule(startIndent = 16.dp)
            InsetGroupedRow(
                title = "DNS",
                trailing = { TabularRowValue(text = formatDnsDetail(settings)) },
            )
            HairlineRule(startIndent = 16.dp)
            InsetGroupedRow(
                title = "QUIC Blocking",
                trailing = { TabularRowValue(text = if (settings.blockQuic) "Enabled" else "Off") },
            )
            HairlineRule(startIndent = 16.dp)
            InsetGroupedRow(
                title = "Split Tunnel",
                trailing = { TabularRowValue(text = splitSummary(settings) ?: "All Apps") },
            )
        }
    }
}

@Composable
private fun TabularRowValue(text: String) {
    val palette = VdpiThemeTokens.palette
    Text(
        text = text,
        style = VdpiTextStyles.monoMetric,
        color = palette.inkSecondary,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
    )
}

// ── Dashboard Glyphs ──

@Composable
private fun TunnelStatusGlyph(
    phase: TunnelPhase,
    tint: Color,
    glyphSize: Dp = 28.dp,
) {
    Canvas(modifier = Modifier.size(glyphSize)) {
        val w = size.width
        val h = size.height
        val strokeWidth = 2.1.dp.toPx()
        val stroke = Stroke(width = strokeWidth, cap = StrokeCap.Round, join = StrokeJoin.Round)

        val shield = Path().apply {
            moveTo(w * 0.50f, h * 0.10f)
            lineTo(w * 0.84f, h * 0.23f)
            lineTo(w * 0.84f, h * 0.49f)
            cubicTo(w * 0.84f, h * 0.72f, w * 0.68f, h * 0.84f, w * 0.50f, h * 0.91f)
            cubicTo(w * 0.32f, h * 0.84f, w * 0.16f, h * 0.72f, w * 0.16f, h * 0.49f)
            lineTo(w * 0.16f, h * 0.23f)
            close()
        }
        drawPath(path = shield, color = tint, style = stroke)

        when (phase) {
            TunnelPhase.CONNECTED -> {
                val check = Path().apply {
                    moveTo(w * 0.35f, h * 0.52f)
                    lineTo(w * 0.46f, h * 0.63f)
                    lineTo(w * 0.66f, h * 0.40f)
                }
                drawPath(path = check, color = tint, style = stroke)
            }

            TunnelPhase.CONNECTING -> {
                val dotR = 1.65.dp.toPx()
                drawCircle(color = tint, radius = dotR, center = Offset(w * 0.37f, h * 0.51f))
                drawCircle(color = tint, radius = dotR, center = Offset(w * 0.50f, h * 0.51f))
                drawCircle(color = tint, radius = dotR, center = Offset(w * 0.63f, h * 0.51f))
            }

            TunnelPhase.ERROR -> {
                drawLine(
                    color = tint,
                    start = Offset(w * 0.50f, h * 0.35f),
                    end = Offset(w * 0.50f, h * 0.56f),
                    strokeWidth = strokeWidth,
                    cap = StrokeCap.Round,
                )
                drawCircle(
                    color = tint,
                    radius = 1.55.dp.toPx(),
                    center = Offset(w * 0.50f, h * 0.67f),
                )
            }

            TunnelPhase.DISCONNECTED -> {
                drawLine(
                    color = tint,
                    start = Offset(w * 0.38f, h * 0.51f),
                    end = Offset(w * 0.62f, h * 0.51f),
                    strokeWidth = strokeWidth,
                    cap = StrokeCap.Round,
                )
            }
        }
    }
}

@Composable
private fun DiagnosticsGlyph(tint: Color) {
    Canvas(modifier = Modifier.size(20.dp)) {
        val w = size.width
        val h = size.height
        val stroke = Stroke(
            width = 1.75.dp.toPx(),
            cap = StrokeCap.Round,
            join = StrokeJoin.Round,
        )
        val pulse = Path().apply {
            moveTo(w * 0.10f, h * 0.54f)
            lineTo(w * 0.30f, h * 0.54f)
            lineTo(w * 0.42f, h * 0.24f)
            lineTo(w * 0.56f, h * 0.78f)
            lineTo(w * 0.68f, h * 0.44f)
            lineTo(w * 0.76f, h * 0.54f)
            lineTo(w * 0.90f, h * 0.54f)
        }
        drawPath(path = pulse, color = tint, style = stroke)
    }
}

@Composable
private fun EngineLogGlyph(tint: Color) {
    Canvas(modifier = Modifier.size(20.dp)) {
        val w = size.width
        val h = size.height
        val strokePx = 1.65.dp.toPx()
        val stroke = Stroke(
            width = strokePx,
            cap = StrokeCap.Round,
            join = StrokeJoin.Round,
        )
        drawRoundRect(
            color = tint,
            topLeft = Offset(w * 0.18f, h * 0.12f),
            size = Size(w * 0.64f, h * 0.76f),
            cornerRadius = CornerRadius(3.dp.toPx(), 3.dp.toPx()),
            style = stroke,
        )
        drawLine(
            color = tint,
            start = Offset(w * 0.32f, h * 0.35f),
            end = Offset(w * 0.68f, h * 0.35f),
            strokeWidth = strokePx,
            cap = StrokeCap.Round,
        )
        drawLine(
            color = tint,
            start = Offset(w * 0.32f, h * 0.51f),
            end = Offset(w * 0.68f, h * 0.51f),
            strokeWidth = strokePx,
            cap = StrokeCap.Round,
        )
        drawLine(
            color = tint,
            start = Offset(w * 0.32f, h * 0.67f),
            end = Offset(w * 0.56f, h * 0.67f),
            strokeWidth = strokePx,
            cap = StrokeCap.Round,
        )
    }
}

@Composable
private fun WarningCircleGlyph(tint: Color) {
    Canvas(modifier = Modifier.size(20.dp)) {
        val w = size.width
        val h = size.height
        val strokePx = 1.8.dp.toPx()
        drawCircle(
            color = tint,
            radius = size.minDimension * 0.44f,
            style = Stroke(width = strokePx),
        )
        drawLine(
            color = tint,
            start = Offset(w * 0.50f, h * 0.28f),
            end = Offset(w * 0.50f, h * 0.54f),
            strokeWidth = strokePx,
            cap = StrokeCap.Round,
        )
        drawCircle(
            color = tint,
            radius = 1.25.dp.toPx(),
            center = Offset(w * 0.50f, h * 0.70f),
        )
    }
}

// ── Formatting Helpers ──

private fun formatHeroUptime(totalSecs: Long): String {
    val safe = totalSecs.coerceAtLeast(0L)
    if (safe >= 3600L) {
        return formatUptime(safe)
    }
    val m = safe / 60L
    val s = safe % 60L
    return String.format(Locale.US, "%02d:%02d", m, s)
}

private fun formatDnsDetail(settings: VdpiSettings): String {
    val addr = settings.dnsAddr.trim().ifBlank { "1.1.1.1" }
    val proto = if (settings.enableDoh) "DoH" else "UDP"
    return "$addr · $proto"
}

private fun splitSummary(settings: VdpiSettings): String? {
    val count = settings.splitPackages.size
    if (count == 0) return null
    return when (settings.splitTunnelMode) {
        SplitTunnelMode.BYPASS_SELECTED -> "$count Bypassed"
        SplitTunnelMode.ONLY_SELECTED -> "$count Routed"
    }
}
