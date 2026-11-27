package com.vulninc.vdpi.ui.screens

import android.content.Intent
import android.content.res.Configuration
import android.net.Uri
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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
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
import com.vulninc.vdpi.ui.components.sculptedDarkCardBorder
import com.vulninc.vdpi.ui.components.springPress
import com.vulninc.vdpi.ui.theme.GeistSans
import com.vulninc.vdpi.ui.theme.VdpiTextStyles
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens
import com.vulninc.vdpi.util.formatBytes
import com.vulninc.vdpi.util.formatStageLabel
import com.vulninc.vdpi.util.formatUptime
import com.vulninc.vdpi.util.isValidDnsInput
import com.vulninc.vdpi.vpn.TunnelPhase
import com.vulninc.vdpi.vpn.TunnelRuntimeSnapshot
import com.vulninc.vdpi.vpn.TunnelRuntimeState
import kotlinx.coroutines.flow.StateFlow
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.Locale

// ── Shared Update Presentation Model ──

data class UpdateBannerInfo(
    val latestVersion: String,
    val releaseUrl: String,
)

internal fun formatVersionTag(version: String): String {
    val trimmed = version.trim()
    if (trimmed.isEmpty()) return ""
    return if (trimmed.startsWith("v", ignoreCase = true)) trimmed else "v$trimmed"
}

// ── Tunnel Dashboard Screen ──

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TunnelScreen(
    tunnelState: StateFlow<TunnelRuntimeSnapshot>,
    throughputSamples: StateFlow<List<Long>>,
    currentRateBytesPerSec: StateFlow<Long>,
    settings: VdpiSettings,
    doctorState: DoctorUiState,
    pendingReconnect: Boolean,
    onToggleTunnel: () -> Unit,
    onReconnect: () -> Unit,
    onRunDoctor: () -> Unit,
    modifier: Modifier = Modifier,
    availableUpdate: UpdateBannerInfo? = null,
    onFormatDiagnosticsReport: () -> String = { "" },
    onDismissUpdate: () -> Unit = {},
) {
    // Scoped locally so 1Hz telemetry updates never recompose MainActivity, Apps, or Settings.
    val runtime by tunnelState.collectAsStateWithLifecycle()
    val appliedSettings by TunnelRuntimeState.appliedSettings.collectAsStateWithLifecycle()
    val samples by throughputSamples.collectAsStateWithLifecycle()
    val currentRate by currentRateBytesPerSec.collectAsStateWithLifecycle()
    val palette = VdpiThemeTokens.palette
    val context = LocalContext.current
    val haptic = LocalHapticFeedback.current
    val reduceMotion = LocalReduceMotion.current

    var showDoctorSheet by rememberSaveable { mutableStateOf(false) }
    var showLogSheet by rememberSaveable { mutableStateOf(false) }
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

    val openUpdateRelease: (String) -> Unit = { url ->
        if (url.isNotBlank()) {
            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
            runCatching {
                context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
            }
        }
    }

    val dismissUpdateWithHaptic: () -> Unit = {
        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
        onDismissUpdate()
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
            appliedSettings = appliedSettings,
            throughputSamples = samples,
            currentRateBytesPerSec = currentRate,
            availableUpdate = availableUpdate,
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
            onDownloadUpdate = openUpdateRelease,
            onDismissUpdate = dismissUpdateWithHaptic,
            modifier = modifier,
        )
    } else {
        PortraitTunnelLayout(
            runtime = runtime,
            settings = settings,
            appliedSettings = appliedSettings,
            throughputSamples = samples,
            currentRateBytesPerSec = currentRate,
            availableUpdate = availableUpdate,
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
            onDownloadUpdate = openUpdateRelease,
            onDismissUpdate = dismissUpdateWithHaptic,
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
                onFormatDiagnosticsReport = onFormatDiagnosticsReport,
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
    appliedSettings: VdpiSettings?,
    throughputSamples: List<Long>,
    currentRateBytesPerSec: Long,
    availableUpdate: UpdateBannerInfo?,
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
    onDownloadUpdate: (String) -> Unit,
    onDismissUpdate: () -> Unit,
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

            PendingReconnectSection(
                visible = pendingReconnect && isConnected,
                reduceMotion = reduceMotion,
                compact = true,
                topSpacing = 0.dp,
                bottomSpacing = 10.dp,
                onReconnect = onReconnect,
            )

            AvailableUpdateSection(
                update = availableUpdate,
                reduceMotion = reduceMotion,
                compact = true,
                topSpacing = 0.dp,
                bottomSpacing = 10.dp,
                onDownload = onDownloadUpdate,
                onDismiss = onDismissUpdate,
            )

            // Adaptive two-pane landscape dashboard
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp),
                verticalAlignment = Alignment.Top,
            ) {
                // Left pane: Compact Hero Card
                Box(modifier = Modifier.weight(0.46f)) {
                    TunnelHeroCard(
                        runtime = runtime,
                        settings = settings,
                        appliedSettings = appliedSettings,
                        reduceMotion = reduceMotion,
                        compact = true,
                        onToggleTunnel = onToggleTunnel,
                    )
                }

                // Right pane: Live Telemetry or Standby Profile beside the Hero Card
                Box(modifier = Modifier.weight(0.54f)) {
                    TunnelDetailsSection(
                        isConnected = isConnected,
                        telemetry = runtime.telemetry,
                        throughputSamples = throughputSamples,
                        currentRateBytesPerSec = currentRateBytesPerSec,
                        settings = settings,
                        appliedSettings = appliedSettings,
                        reduceMotion = reduceMotion,
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
    appliedSettings: VdpiSettings?,
    throughputSamples: List<Long>,
    currentRateBytesPerSec: Long,
    availableUpdate: UpdateBannerInfo?,
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
    onDownloadUpdate: (String) -> Unit,
    onDismissUpdate: () -> Unit,
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

        // Primary tunnel status card
        TunnelHeroCard(
            runtime = runtime,
            settings = settings,
            appliedSettings = appliedSettings,
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

        // Dismissible update card when a newer GitHub release is available
        AvailableUpdateSection(
            update = availableUpdate,
            reduceMotion = reduceMotion,
            compact = false,
            onDownload = onDownloadUpdate,
            onDismiss = onDismissUpdate,
        )

        Spacer(Modifier.height(24.dp))

        // Inset Grouped Telemetry or Standby Profile
        TunnelDetailsSection(
            isConnected = isConnected,
            telemetry = runtime.telemetry,
            throughputSamples = throughputSamples,
            currentRateBytesPerSec = currentRateBytesPerSec,
            settings = settings,
            appliedSettings = appliedSettings,
            reduceMotion = reduceMotion,
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
    topSpacing: Dp = if (compact) 10.dp else 12.dp,
    bottomSpacing: Dp = 0.dp,
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
            if (topSpacing > 0.dp) {
                Spacer(Modifier.height(topSpacing))
            }
            InlineReconnectRow(
                compact = compact,
                onReconnect = onReconnect,
            )
            if (bottomSpacing > 0.dp) {
                Spacer(Modifier.height(bottomSpacing))
            }
        }
    }
}

@Composable
private fun AvailableUpdateSection(
    update: UpdateBannerInfo?,
    reduceMotion: Boolean,
    compact: Boolean,
    onDownload: (String) -> Unit,
    onDismiss: () -> Unit,
    topSpacing: Dp = if (compact) 10.dp else 12.dp,
    bottomSpacing: Dp = 0.dp,
) {
    var lastUpdate by remember { mutableStateOf(update) }
    if (update != null) {
        lastUpdate = update
    }
    AnimatedVisibility(
        visible = update != null,
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
        val current = lastUpdate
        if (current != null) {
            Column {
                if (topSpacing > 0.dp) {
                    Spacer(Modifier.height(topSpacing))
                }
                InlineUpdateRow(
                    update = current,
                    compact = compact,
                    onDownload = { onDownload(current.releaseUrl) },
                    onDismiss = onDismiss,
                )
                if (bottomSpacing > 0.dp) {
                    Spacer(Modifier.height(bottomSpacing))
                }
            }
        }
    }
}

@Composable
private fun TunnelDetailsSection(
    isConnected: Boolean,
    telemetry: TelemetrySnapshot,
    throughputSamples: List<Long>,
    currentRateBytesPerSec: Long,
    settings: VdpiSettings,
    appliedSettings: VdpiSettings?,
    reduceMotion: Boolean,
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
                throughputSamples = throughputSamples,
                currentRateBytesPerSec = currentRateBytesPerSec,
                settings = settings,
                appliedSettings = appliedSettings,
                reduceMotion = reduceMotion,
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
    appliedSettings: VdpiSettings?,
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

    val activeDnsAddr = snap.dnsAddr.trim().ifBlank { (appliedSettings ?: settings).dnsAddr }
    val activeDoh = isEffectiveDohTarget(activeDnsAddr, snap.dohEnabled)
    val dnsCompact = "${formatDnsDisplayAddr(activeDnsAddr)} ${if (activeDoh) "DoH" else "UDP"}"
    val subtitle = when (phase) {
        TunnelPhase.CONNECTED -> "$dnsCompact · ${formatHeroUptime(snap.uptimeSecs)}"
        TunnelPhase.CONNECTING -> "Establishing local tunnel..."
        TunnelPhase.DISCONNECTED -> "Local anti-DPI tunnel ready"
        TunnelPhase.ERROR -> runtime.errorMessage?.takeIf { it.isNotBlank() } ?: "Tunnel stopped unexpectedly"
    }

    InsetGroupedCard(
        modifier = Modifier
            .fillMaxWidth()
            .sculptedDarkCardBorder(16.dp),
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
                        textDirection = if (phase == TunnelPhase.CONNECTED) {
                            TextDirection.Ltr
                        } else {
                            TextDirection.Unspecified
                        },
                    )
                } else {
                    VdpiTextStyles.body.copy(
                        fontFeatureSettings = "tnum",
                        textDirection = if (phase == TunnelPhase.CONNECTED) {
                            TextDirection.Ltr
                        } else {
                            TextDirection.Unspecified
                        },
                    )
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
        modifier = Modifier
            .fillMaxWidth()
            .sculptedDarkCardBorder(16.dp),
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

// ── Inline Update Row ──

@Composable
private fun InlineUpdateRow(
    update: UpdateBannerInfo,
    onDownload: () -> Unit,
    onDismiss: () -> Unit,
    compact: Boolean = false,
) {
    val palette = VdpiThemeTokens.palette
    val downloadInteraction = remember { MutableInteractionSource() }
    val downloadPressed by downloadInteraction.collectIsPressedAsState()
    val downloadColor by animateColorAsState(
        targetValue = if (downloadPressed) palette.accent.copy(alpha = 0.65f) else palette.accent,
        animationSpec = tween(durationMillis = if (downloadPressed) 60 else 150),
        label = "updateDownloadColor",
    )
    val dismissInteraction = remember { MutableInteractionSource() }
    val dismissPressed by dismissInteraction.collectIsPressedAsState()
    val dismissWash by animateColorAsState(
        targetValue = if (dismissPressed) palette.inkPrimary.copy(alpha = 0.08f) else Color.Transparent,
        animationSpec = tween(durationMillis = if (dismissPressed) 60 else 150),
        label = "updateDismissWash",
    )
    val versionTag = formatVersionTag(update.latestVersion)

    InsetGroupedCard(
        modifier = Modifier
            .fillMaxWidth()
            .sculptedDarkCardBorder(16.dp),
        radius = 16.dp,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(
                    start = if (compact) 12.dp else 16.dp,
                    end = 4.dp,
                    top = if (compact) 6.dp else 8.dp,
                    bottom = if (compact) 6.dp else 8.dp,
                ),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(6.dp)
                    .clip(CircleShape)
                    .background(palette.accent),
            )

            Spacer(Modifier.width(if (compact) 10.dp else 12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Update available",
                    style = VdpiTextStyles.body.copy(fontWeight = FontWeight.SemiBold),
                    color = palette.inkPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(Modifier.height(1.dp))
                Text(
                    text = "$versionTag on GitHub",
                    style = VdpiTextStyles.caption,
                    color = palette.inkSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Spacer(Modifier.width(6.dp))

            Box(
                modifier = Modifier
                    .heightIn(min = 44.dp)
                    .clickable(
                        interactionSource = downloadInteraction,
                        indication = null,
                        role = Role.Button,
                        onClick = onDownload,
                    )
                    .padding(horizontal = 8.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = "Download",
                    fontFamily = GeistSans,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 14.sp,
                    color = downloadColor,
                    maxLines = 1,
                )
            }

            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clickable(
                        interactionSource = dismissInteraction,
                        indication = null,
                        role = Role.Button,
                        onClick = onDismiss,
                    )
                    .semantics { contentDescription = "Dismiss update notice" },
                contentAlignment = Alignment.Center,
            ) {
                Box(
                    modifier = Modifier
                        .size(28.dp)
                        .clip(CircleShape)
                        .background(dismissWash),
                    contentAlignment = Alignment.Center,
                ) {
                    DismissCrossGlyph(tint = palette.inkMuted)
                }
            }
        }
    }
}

// ── Live Telemetry & Standby Profile ──

@Composable
private fun LiveTelemetrySection(
    telemetry: TelemetrySnapshot,
    throughputSamples: List<Long>,
    currentRateBytesPerSec: Long,
    settings: VdpiSettings,
    appliedSettings: VdpiSettings?,
    reduceMotion: Boolean,
) {
    val effectiveSettings = appliedSettings ?: settings
    val activeDnsAddr = telemetry.dnsAddr.trim().ifBlank { effectiveSettings.dnsAddr }
    Column(modifier = Modifier.fillMaxWidth()) {
        SectionOverline(text = "Connection")

        InsetGroupedCard(
            modifier = Modifier
                .fillMaxWidth()
                .sculptedDarkCardBorder(16.dp),
            radius = 16.dp,
        ) {
            InsetGroupedRow(
                title = "Download",
                trailing = {
                    AnimatedTabularValue(
                        text = formatBytes(telemetry.bytesRx),
                        reduceMotion = reduceMotion,
                    )
                },
            )
            HairlineRule(startIndent = 16.dp)
            InsetGroupedRow(
                title = "Upload",
                trailing = {
                    AnimatedTabularValue(
                        text = formatBytes(telemetry.bytesTx),
                        reduceMotion = reduceMotion,
                    )
                },
            )
            HairlineRule(startIndent = 16.dp)
            InsetGroupedRow(
                title = "Uptime",
                trailing = {
                    AnimatedTabularValue(
                        text = formatUptime(telemetry.uptimeSecs),
                        reduceMotion = reduceMotion,
                    )
                },
            )
            HairlineRule(startIndent = 16.dp)
            ThroughputSparkline(
                samples = throughputSamples,
                currentRateBytesPerSec = currentRateBytesPerSec,
                reduceMotion = reduceMotion,
            )
            HairlineRule(startIndent = 16.dp)
            InsetGroupedRow(
                title = "Strategy",
                trailing = { TabularRowValue(text = formatStageLabel(telemetry.stageLabel)) },
            )
            HairlineRule(startIndent = 16.dp)
            InsetGroupedRow(
                title = "DNS",
                trailing = {
                    TabularRowValue(
                        text = formatDnsDetail(activeDnsAddr, telemetry.dohEnabled),
                        textDirection = TextDirection.Ltr,
                    )
                },
            )
            HairlineRule(startIndent = 16.dp)
            InsetGroupedRow(
                title = "QUIC Blocked",
                trailing = {
                    TabularRowValue(
                        text = if (effectiveSettings.blockQuic) telemetry.quicBlocked.toString() else "Allowed",
                    )
                },
            )
            HairlineRule(startIndent = 16.dp)
            InsetGroupedRow(
                title = "Dropped Packets",
                trailing = {
                    TabularRowValue(
                        text = telemetry.droppedPackets.coerceAtLeast(0L).toString(),
                    )
                },
            )
        }
    }
}

@Composable
private fun ThroughputSparkline(
    samples: List<Long>,
    currentRateBytesPerSec: Long,
    reduceMotion: Boolean,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    val lineColor = palette.signal
    val baselineColor = palette.border.copy(alpha = 0.55f)
    val rateLabel = formatRate(currentRateBytesPerSec)
    val strokePath = remember { Path() }
    val fillPath = remember { Path() }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = "Activity",
                style = VdpiTextStyles.caption,
                color = palette.inkMuted,
                maxLines = 1,
            )
            AnimatedTabularValue(
                text = rateLabel,
                reduceMotion = reduceMotion,
                style = VdpiTextStyles.monoSmall.copy(
                    fontWeight = FontWeight.Medium,
                    fontSize = 12.sp,
                ),
                color = palette.inkSecondary,
            )
        }

        Spacer(Modifier.height(8.dp))

        Canvas(
            modifier = Modifier
                .fillMaxWidth()
                .height(44.dp)
                .semantics { contentDescription = "Live throughput $rateLabel" },
        ) {
            val w = size.width
            val h = size.height
            if (w <= 0f || h <= 0f) return@Canvas

            val baselineY = h - 1.dp.toPx()
            val baselineStrokePx = 0.5.dp.toPx()
            drawLine(
                color = baselineColor,
                start = Offset(0f, baselineY),
                end = Offset(w, baselineY),
                strokeWidth = baselineStrokePx,
            )

            val maxSample = samples.maxOrNull()?.coerceAtLeast(0L) ?: 0L
            if (samples.isEmpty() || maxSample <= 0L) {
                return@Canvas
            }

            val topPad = 3.dp.toPx()
            val usableH = (baselineY - topPad).coerceAtLeast(1f)
            val lineStroke = Stroke(
                width = 1.5.dp.toPx(),
                cap = StrokeCap.Round,
                join = StrokeJoin.Round,
            )

            strokePath.reset()
            fillPath.reset()

            if (samples.size == 1) {
                val ratio = (samples[0].coerceAtLeast(0L).toDouble() / maxSample.toDouble()).toFloat()
                val y = baselineY - ratio * usableH
                strokePath.moveTo(0f, y)
                strokePath.lineTo(w, y)

                fillPath.moveTo(0f, y)
                fillPath.lineTo(w, y)
                fillPath.lineTo(w, baselineY)
                fillPath.lineTo(0f, baselineY)
                fillPath.close()
            } else {
                val count = samples.size
                val stepX = w / (count - 1).toFloat()
                var prevX = 0f
                var prevY = baselineY - (samples[0].coerceAtLeast(0L).toDouble() / maxSample.toDouble()).toFloat() * usableH

                strokePath.moveTo(prevX, prevY)
                fillPath.moveTo(prevX, prevY)

                for (i in 1 until count) {
                    val currX = i * stepX
                    val ratio = (samples[i].coerceAtLeast(0L).toDouble() / maxSample.toDouble()).toFloat()
                    val currY = baselineY - ratio * usableH
                    val midX = (prevX + currX) * 0.5f
                    val midY = (prevY + currY) * 0.5f
                    if (i == 1) {
                        strokePath.lineTo(midX, midY)
                        fillPath.lineTo(midX, midY)
                    } else {
                        strokePath.quadraticTo(prevX, prevY, midX, midY)
                        fillPath.quadraticTo(prevX, prevY, midX, midY)
                    }
                    prevX = currX
                    prevY = currY
                }

                strokePath.lineTo(prevX, prevY)
                fillPath.lineTo(prevX, prevY)
                fillPath.lineTo(prevX, baselineY)
                fillPath.lineTo(0f, baselineY)
                fillPath.close()
            }

            drawPath(
                path = fillPath,
                brush = Brush.verticalGradient(
                    colors = listOf(
                        lineColor.copy(alpha = 0.10f),
                        Color.Transparent,
                    ),
                    startY = topPad,
                    endY = baselineY,
                ),
            )
            drawPath(
                path = strokePath,
                color = lineColor,
                style = lineStroke,
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
            modifier = Modifier
                .fillMaxWidth()
                .sculptedDarkCardBorder(16.dp),
            radius = 16.dp,
        ) {
            InsetGroupedRow(
                title = "Mode",
                trailing = { TabularRowValue(text = settings.desyncMode.label) },
            )
            HairlineRule(startIndent = 16.dp)
            InsetGroupedRow(
                title = "DNS",
                trailing = {
                    TabularRowValue(
                        text = formatDnsDetail(settings.dnsAddr, settings.enableDoh),
                        textDirection = TextDirection.Ltr,
                    )
                },
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
private fun AnimatedTabularValue(
    text: String,
    reduceMotion: Boolean,
    style: TextStyle = VdpiTextStyles.monoMetric,
    color: Color = VdpiThemeTokens.palette.inkSecondary,
) {
    if (reduceMotion) {
        Text(
            text = text,
            style = style,
            color = color,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    } else {
        AnimatedContent(
            targetState = text,
            transitionSpec = {
                fadeIn(tween(140)) togetherWith fadeOut(tween(110))
            },
            label = "tabularMetricTransition",
        ) { value ->
            Text(
                text = value,
                style = style,
                color = color,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun TabularRowValue(
    text: String,
    modifier: Modifier = Modifier,
    textDirection: TextDirection = TextDirection.Unspecified,
) {
    val palette = VdpiThemeTokens.palette
    Text(
        text = text,
        style = if (textDirection != TextDirection.Unspecified) {
            VdpiTextStyles.monoMetric.copy(textDirection = textDirection)
        } else {
            VdpiTextStyles.monoMetric
        },
        color = palette.inkSecondary,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
        modifier = modifier.widthIn(max = 190.dp),
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
    val isRtl = LocalLayoutDirection.current == LayoutDirection.Rtl
    Canvas(
        modifier = Modifier
            .size(20.dp)
            .graphicsLayer { if (isRtl) scaleX = -1f },
    ) {
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

@Composable
private fun DismissCrossGlyph(tint: Color) {
    Canvas(modifier = Modifier.size(11.dp)) {
        val stroke = 1.7.dp.toPx()
        val inset = stroke * 0.5f
        drawLine(
            color = tint,
            start = Offset(inset, inset),
            end = Offset(size.width - inset, size.height - inset),
            strokeWidth = stroke,
            cap = StrokeCap.Round,
        )
        drawLine(
            color = tint,
            start = Offset(size.width - inset, inset),
            end = Offset(inset, size.height - inset),
            strokeWidth = stroke,
            cap = StrokeCap.Round,
        )
    }
}

// ── Formatting Helpers ──

private fun formatRate(bytesPerSec: Long): String {
    val safe = bytesPerSec.coerceAtLeast(0L)
    if (safe < 1024L) return "$safe B/s"
    val kb = safe / 1024.0
    if (kb < 100.0) return String.format(Locale.US, "%.1f KB/s", kb)
    if (kb < 1024.0) return String.format(Locale.US, "%.0f KB/s", kb)
    val mb = kb / 1024.0
    if (mb < 100.0) return String.format(Locale.US, "%.1f MB/s", mb)
    if (mb < 1024.0) return String.format(Locale.US, "%.0f MB/s", mb)
    return String.format(Locale.US, "%.2f GB/s", mb / 1024.0)
}

private fun formatHeroUptime(totalSecs: Long): String {
    val safe = totalSecs.coerceAtLeast(0L)
    if (safe >= 3600L) {
        return formatUptime(safe)
    }
    val m = safe / 60L
    val s = safe % 60L
    return String.format(Locale.US, "%02d:%02d", m, s)
}

private fun formatDnsDisplayAddr(rawAddr: String): String {
    val addr = rawAddr.trim().ifBlank { "1.1.1.1" }
    return if (addr.startsWith("https://", ignoreCase = true)) {
        runCatching { java.net.URI(addr).host }.getOrNull()?.takeIf { it.isNotBlank() } ?: "custom DoH"
    } else {
        addr
    }
}

private fun isKnownPublicDohIp(rawIp: String): Boolean {
    val trimmed = rawIp.trim()
    if (trimmed.isEmpty() || trimmed.startsWith("https://", ignoreCase = true)) return false
    if (!isValidDnsInput(trimmed)) return false
    val unbracketed = if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
        trimmed.substring(1, trimmed.length - 1)
    } else {
        trimmed
    }
    val addr = runCatching { InetAddress.getByName(unbracketed) }.getOrNull() ?: return false
    return when (addr) {
        is Inet4Address -> {
            val b = addr.address
            if (b.size != 4) return false
            val b0 = b[0].toInt() and 0xFF
            val b1 = b[1].toInt() and 0xFF
            val b2 = b[2].toInt() and 0xFF
            val b3 = b[3].toInt() and 0xFF
            (b0 == 1 && b1 == 1 && b2 == 1 && b3 in 1..3) ||
                (b0 == 1 && b1 == 0 && b2 == 0 && b3 in 1..3) ||
                (b0 == 8 && b1 == 8 && ((b2 == 8 && b3 == 8) || (b2 == 4 && b3 == 4))) ||
                (b0 == 9 && b1 == 9 && b2 == 9 && b3 == 9) ||
                (b0 == 149 && b1 == 112 && b2 == 112 && b3 == 112) ||
                (b0 == 94 && b1 == 140 && b2 == 14 && (b3 == 14 || b3 == 15 || b3 == 140 || b3 == 141)) ||
                (b0 == 94 && b1 == 140 && b2 == 15 && (b3 == 15 || b3 == 16))
        }
        is Inet6Address -> {
            val b = addr.address
            if (b.size != 16) return false
            val s0 = ((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)
            val s1 = ((b[2].toInt() and 0xFF) shl 8) or (b[3].toInt() and 0xFF)
            val s2 = ((b[4].toInt() and 0xFF) shl 8) or (b[5].toInt() and 0xFF)
            val s3 = ((b[6].toInt() and 0xFF) shl 8) or (b[7].toInt() and 0xFF)
            val s4 = ((b[8].toInt() and 0xFF) shl 8) or (b[9].toInt() and 0xFF)
            val s5 = ((b[10].toInt() and 0xFF) shl 8) or (b[11].toInt() and 0xFF)
            val s6 = ((b[12].toInt() and 0xFF) shl 8) or (b[13].toInt() and 0xFF)
            val s7 = ((b[14].toInt() and 0xFF) shl 8) or (b[15].toInt() and 0xFF)
            if (s3 != 0 || s4 != 0 || s5 != 0) return false
            when {
                s0 == 0x2606 && s1 == 0x4700 && s2 == 0x4700 && s6 == 0 ->
                    s7 == 0x1111 || s7 == 0x1001 || s7 == 0x1112 || s7 == 0x1002 || s7 == 0x1113 || s7 == 0x1003
                s0 == 0x2001 && s1 == 0x4860 && s2 == 0x4860 && s6 == 0 ->
                    s7 == 0x8888 || s7 == 0x8844
                s0 == 0x2620 && s1 == 0x00fe && s2 == 0 && s6 == 0 ->
                    s7 == 0x00fe || s7 == 0x0009
                s0 == 0x2a10 && s1 == 0x50c0 && s2 == 0 && s7 == 0x00ff ->
                    s6 == 0x0ad1 || s6 == 0x0ad2 || s6 == 0xbad1 || s6 == 0xbad2 || s6 == 0x0001 || s6 == 0x0002
                else -> false
            }
        }
        else -> false
    }
}

internal fun isEffectiveDohTarget(rawAddr: String, enableDoh: Boolean): Boolean {
    val trimmed = rawAddr.trim().ifBlank { "1.1.1.1" }
    if (trimmed.startsWith("https://", ignoreCase = true)) {
        if (trimmed.equals("https://<redacted>", ignoreCase = true)) return true
        val candidate = if (trimmed.endsWith("/<redacted>", ignoreCase = true)) {
            trimmed.dropLast("/<redacted>".length)
        } else {
            trimmed
        }
        return isValidDnsInput(candidate)
    }
    if (!enableDoh) return false
    return isKnownPublicDohIp(trimmed)
}

private fun formatDnsDetail(rawAddr: String, enableDoh: Boolean): String {
    val addr = formatDnsDisplayAddr(rawAddr)
    val proto = if (isEffectiveDohTarget(rawAddr, enableDoh)) "DoH" else "UDP"
    return "$addr · $proto"
}

internal fun splitSummary(settings: VdpiSettings): String? {
    val count = settings.splitPackages.size
    return when (settings.splitTunnelMode) {
        SplitTunnelMode.BYPASS_SELECTED -> if (count == 0) null else "$count Bypassed"
        SplitTunnelMode.ONLY_SELECTED -> if (count == 0) "0 apps (none protected)" else "$count Routed"
    }
}
