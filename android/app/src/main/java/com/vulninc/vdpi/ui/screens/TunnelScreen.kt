package com.vulninc.vdpi.ui.screens

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
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
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
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.vulninc.vdpi.BuildConfig
import com.vulninc.vdpi.data.SplitTunnelMode
import com.vulninc.vdpi.data.VdpiSettings
import com.vulninc.vdpi.engine.EngineEvent
import com.vulninc.vdpi.engine.TelemetrySnapshot
import com.vulninc.vdpi.ui.DoctorUiState
import com.vulninc.vdpi.ui.components.AuroraHeroBackground
import com.vulninc.vdpi.ui.components.FloatingGlassIconButton
import com.vulninc.vdpi.ui.components.GhostActionButton
import com.vulninc.vdpi.ui.components.HairlineRule
import com.vulninc.vdpi.ui.components.LiquidGlassCapsule
import com.vulninc.vdpi.ui.components.LiquidGlassCard
import com.vulninc.vdpi.ui.components.LocalBottomChromePadding
import com.vulninc.vdpi.ui.components.LocalTopOverlayPadding
import com.vulninc.vdpi.ui.components.SectionOverline
import com.vulninc.vdpi.ui.components.VdpiBrandMark
import com.vulninc.vdpi.ui.components.springPress
import com.vulninc.vdpi.ui.theme.GeistMono
import com.vulninc.vdpi.ui.theme.GeistSans
import com.vulninc.vdpi.ui.theme.VdpiTextStyles
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens
import com.vulninc.vdpi.util.formatBytes
import com.vulninc.vdpi.util.formatEventTime
import com.vulninc.vdpi.util.formatStageShort
import com.vulninc.vdpi.util.formatUptime
import com.vulninc.vdpi.vpn.TunnelPhase
import com.vulninc.vdpi.vpn.TunnelRuntimeSnapshot
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TunnelScreen(
    tunnelState: StateFlow<TunnelRuntimeSnapshot>,
    settings: VdpiSettings,
    doctorState: DoctorUiState,
    engineVersion: String = BuildConfig.VERSION_NAME,
    pendingReconnect: Boolean,
    onToggleTunnel: () -> Unit,
    onReconnect: () -> Unit,
    onRunDoctor: () -> Unit,
    onClearCache: () -> Unit,
    modifier: Modifier = Modifier,
) {
    // Scoped locally so 1Hz telemetry updates never recompose MainActivity, Apps, or Settings.
    val runtime by tunnelState.collectAsStateWithLifecycle()
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    var showDoctorSheet by remember { mutableStateOf(false) }
    var showLogSheet by remember { mutableStateOf(false) }
    var cacheClearedFeedback by remember { mutableStateOf(false) }

    LaunchedEffect(cacheClearedFeedback) {
        if (cacheClearedFeedback) {
            delay(2000L)
            cacheClearedFeedback = false
        }
    }

    val isConnected = runtime.phase == TunnelPhase.CONNECTED
    val isConnecting = runtime.phase == TunnelPhase.CONNECTING
    val versionLabel = engineVersion.ifBlank { BuildConfig.VERSION_NAME }

    val doctorBadgeColor: Color? = when {
        doctorState.running -> palette.warning
        doctorState.report == null -> null
        !doctorState.report.ok || doctorState.report.checks.any { !it.passed } -> palette.danger
        else -> palette.signal
    }

    val openDiagnostics: () -> Unit = {
        showDoctorSheet = true
        if (doctorState.report == null && !doctorState.running) {
            onRunDoctor()
        }
    }

    val triggerClearCache: () -> Unit = {
        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
        onClearCache()
        cacheClearedFeedback = true
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .statusBarsPadding()
            .padding(horizontal = 20.dp),
    ) {
        Spacer(Modifier.height(LocalTopOverlayPadding.current))
        Spacer(Modifier.height(12.dp))

        // Header bar: bold display wordmark + version glass pill + floating circular glass actions
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f),
            ) {
                VdpiBrandMark(active = isConnected, size = 26.dp)
                Spacer(Modifier.width(10.dp))
                Text(
                    text = "vdpi",
                    style = VdpiTextStyles.pageTitle,
                    color = palette.inkPrimary,
                    maxLines = 1,
                )
                Spacer(Modifier.width(10.dp))
                LiquidGlassCapsule(elevated = false) {
                    Text(
                        text = "v$versionLabel",
                        style = VdpiTextStyles.monoSmall,
                        color = palette.inkSecondary,
                        maxLines = 1,
                        modifier = Modifier.padding(horizontal = 9.dp, vertical = 4.dp),
                    )
                }
            }

            Spacer(Modifier.width(12.dp))

            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                FloatingGlassIconButton(
                    onClick = openDiagnostics,
                    contentDescription = "Diagnostics",
                    size = 44.dp,
                    badgeColor = doctorBadgeColor,
                ) {
                    DiagnosticsGlyph(tint = palette.inkPrimary)
                }

                FloatingGlassIconButton(
                    onClick = { showLogSheet = true },
                    contentDescription = "Engine logs",
                    size = 44.dp,
                    badgeColor = if (runtime.telemetry.events.isNotEmpty()) palette.accent else null,
                ) {
                    EngineLogGlyph(tint = palette.inkPrimary)
                }
            }
        }

        Spacer(Modifier.height(20.dp))

        // Organic Aurora Mesh-Gradient Hero Card
        AuroraHeroCard(
            runtime = runtime,
            settings = settings,
            onToggleTunnel = {
                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                onToggleTunnel()
            },
        )

        // Persistent Home Inline Reconnect Card
        AnimatedVisibility(
            visible = pendingReconnect && isConnected,
            enter = fadeIn(tween(200)) + expandVertically(tween(220)),
            exit = fadeOut(tween(150)) + shrinkVertically(tween(180)),
        ) {
            Column {
                Spacer(Modifier.height(14.dp))
                InlineReconnectCard(
                    onReconnect = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        onReconnect()
                    },
                )
            }
        }

        Spacer(Modifier.height(22.dp))

        // Smooth crossfade between Standby Profile and Live Telemetry
        AnimatedContent(
            targetState = isConnected || isConnecting,
            transitionSpec = {
                fadeIn(tween(200)) togetherWith fadeOut(tween(140))
            },
            label = "telemetryPanelTransition",
        ) { live ->
            if (live) {
                LiveTelemetrySection(
                    telemetry = runtime.telemetry,
                    settings = settings,
                    isConnected = isConnected,
                    cacheClearedFeedback = cacheClearedFeedback,
                    onClearCache = triggerClearCache,
                )
            } else {
                StandbyProfileSection(
                    settings = settings,
                    cacheClearedFeedback = cacheClearedFeedback,
                    onOpenDiagnostics = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        openDiagnostics()
                    },
                    onClearCache = triggerClearCache,
                )
            }
        }

        Spacer(Modifier.height(20.dp))
        Spacer(Modifier.height(LocalBottomChromePadding.current))
    }

    if (showDoctorSheet) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(
            onDismissRequest = { showDoctorSheet = false },
            sheetState = sheetState,
            shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
            containerColor = palette.surfaceRaised,
            contentColor = palette.inkPrimary,
        ) {
            DoctorSheetContent(
                doctorState = doctorState,
                onRerun = onRunDoctor,
            )
        }
    }

    if (showLogSheet) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(
            onDismissRequest = { showLogSheet = false },
            sheetState = sheetState,
            shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
            containerColor = palette.surfaceRaised,
            contentColor = palette.inkPrimary,
        ) {
            EngineLogSheetContent(
                events = runtime.telemetry.events,
                onClearCache = onClearCache,
            )
        }
    }
}

@Composable
private fun AuroraHeroCard(
    runtime: TunnelRuntimeSnapshot,
    settings: VdpiSettings,
    onToggleTunnel: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val phase = runtime.phase
    val snap = runtime.telemetry
    val isConnected = phase == TunnelPhase.CONNECTED
    val isConnecting = phase == TunnelPhase.CONNECTING
    val isError = phase == TunnelPhase.ERROR
    val isAuroraPhase = phase != TunnelPhase.DISCONNECTED
    val heroShape = RoundedCornerShape(28.dp)

    val rimTop by animateColorAsState(
        targetValue = when (phase) {
            TunnelPhase.CONNECTED -> Color(0xA634D399)
            TunnelPhase.CONNECTING -> Color(0xA6FBBF24)
            TunnelPhase.ERROR -> Color(0xA6FB7185)
            TunnelPhase.DISCONNECTED -> palette.glassRimTop
        },
        animationSpec = tween(280),
        label = "heroRimTop",
    )
    val rimMid by animateColorAsState(
        targetValue = when (phase) {
            TunnelPhase.CONNECTED -> Color(0x4510B981)
            TunnelPhase.CONNECTING -> Color(0x45F59E0B)
            TunnelPhase.ERROR -> Color(0x45F43F5E)
            TunnelPhase.DISCONNECTED -> palette.glassRimSide
        },
        animationSpec = tween(280),
        label = "heroRimMid",
    )
    val rimBottom by animateColorAsState(
        targetValue = when (phase) {
            TunnelPhase.CONNECTED -> Color(0x2806B6D4)
            TunnelPhase.CONNECTING -> Color(0x24D97706)
            TunnelPhase.ERROR -> Color(0x26E11D48)
            TunnelPhase.DISCONNECTED -> palette.glassRimBottom
        },
        animationSpec = tween(280),
        label = "heroRimBottom",
    )
    val glowColor by animateColorAsState(
        targetValue = when (phase) {
            TunnelPhase.CONNECTED -> palette.signalGlow
            TunnelPhase.CONNECTING -> palette.warningGlow
            TunnelPhase.ERROR -> palette.dangerGlow
            TunnelPhase.DISCONNECTED -> palette.glassShadow
        },
        animationSpec = tween(280),
        label = "heroGlow",
    )

    // High-contrast ink rules: saturated jewel aurora uses crisp white in both light & dark themes.
    val heroInkPrimary by animateColorAsState(
        targetValue = if (isAuroraPhase) Color(0xFFFFFFFF) else palette.inkPrimary,
        animationSpec = tween(220),
        label = "heroInkPrimary",
    )
    val heroInkSecondary by animateColorAsState(
        targetValue = if (isAuroraPhase) Color(0xD9FFFFFF) else palette.inkSecondary,
        animationSpec = tween(220),
        label = "heroInkSecondary",
    )
    val heroPillBg by animateColorAsState(
        targetValue = when {
            isAuroraPhase -> Color(0x33000000)
            palette.isDark -> Color(0x1EFFFFFF)
            else -> Color(0x120A0F1A)
        },
        animationSpec = tween(220),
        label = "heroPillBg",
    )
    val heroPillBorder by animateColorAsState(
        targetValue = when {
            isAuroraPhase -> Color(0x3DFFFFFF)
            palette.isDark -> Color(0x2BFFFFFF)
            else -> palette.border
        },
        animationSpec = tween(220),
        label = "heroPillBorder",
    )
    val beaconColor by animateColorAsState(
        targetValue = when (phase) {
            TunnelPhase.CONNECTED -> Color(0xFF34D399)
            TunnelPhase.CONNECTING -> Color(0xFFFBBF24)
            TunnelPhase.ERROR -> Color(0xFFFB7185)
            TunnelPhase.DISCONNECTED -> palette.inkMuted
        },
        animationSpec = tween(220),
        label = "heroBeacon",
    )

    val borderBrush = Brush.verticalGradient(listOf(rimTop, rimMid, rimBottom))

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .shadow(
                elevation = if (isAuroraPhase) 18.dp else 12.dp,
                shape = heroShape,
                clip = false,
                ambientColor = glowColor,
                spotColor = glowColor,
            )
            .clip(heroShape)
            .border(1.dp, borderBrush, heroShape),
    ) {
        AuroraHeroBackground(
            phase = phase,
            modifier = Modifier.matchParentSize(),
        )

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(22.dp),
        ) {
            // Top micro-status row
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Row(
                    modifier = Modifier
                        .clip(CircleShape)
                        .background(heroPillBg)
                        .border(1.dp, heroPillBorder, CircleShape)
                        .padding(horizontal = 10.dp, vertical = 5.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    StatusBeacon(
                        color = beaconColor,
                        pulsing = isConnected || isConnecting,
                    )
                    Spacer(Modifier.width(7.dp))
                    Text(
                        text = when (phase) {
                            TunnelPhase.CONNECTED -> "PROTECTED"
                            TunnelPhase.CONNECTING -> "CONNECTING"
                            TunnelPhase.DISCONNECTED -> "STANDBY"
                            TunnelPhase.ERROR -> "FAULT"
                        },
                        style = VdpiTextStyles.overline,
                        color = heroInkPrimary,
                    )
                }

                Spacer(Modifier.width(8.dp))

                val strategyText = if (isConnected) {
                    formatStageShort(snap.stageNumber, snap.stageLabel).replaceFirst("Stage ", "S")
                } else {
                    settings.desyncMode.label
                }
                Box(
                    modifier = Modifier
                        .clip(CircleShape)
                        .background(heroPillBg)
                        .border(1.dp, heroPillBorder, CircleShape)
                        .padding(horizontal = 10.dp, vertical = 5.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = strategyText,
                        style = VdpiTextStyles.monoSmall,
                        fontWeight = FontWeight.Medium,
                        color = heroInkSecondary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }

            Spacer(Modifier.height(20.dp))

            // Focal animated status title
            AnimatedContent(
                targetState = phase,
                transitionSpec = {
                    (fadeIn(tween(220)) + slideInVertically(tween(220)) { it / 6 }) togetherWith
                        (fadeOut(tween(140)) + slideOutVertically(tween(140)) { -it / 6 })
                },
                label = "heroStatusTitle",
            ) { currentPhase ->
                Text(
                    text = when (currentPhase) {
                        TunnelPhase.CONNECTED -> "Protected"
                        TunnelPhase.CONNECTING -> "Establishing Tunnel"
                        TunnelPhase.DISCONNECTED -> "Ready to Shield"
                        TunnelPhase.ERROR -> "Connection Error"
                    },
                    style = VdpiTextStyles.hero,
                    color = heroInkPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Spacer(Modifier.height(6.dp))

            val dnsLabel = if (settings.enableDoh) "DoH ${settings.dnsAddr}" else "UDP ${settings.dnsAddr}"
            val subtitle = when (phase) {
                TunnelPhase.CONNECTED -> "Up ${formatUptime(snap.uptimeSecs)} · $dnsLabel"
                TunnelPhase.CONNECTING -> "Starting local TUN engine · $dnsLabel"
                TunnelPhase.ERROR -> runtime.errorMessage?.takeIf { it.isNotBlank() } ?: "Tunnel stopped unexpectedly"
                TunnelPhase.DISCONNECTED -> {
                    val splitNote = splitSummary(settings)
                    if (splitNote != null) {
                        "${settings.desyncMode.label} · $dnsLabel · $splitNote"
                    } else {
                        "${settings.desyncMode.label} · $dnsLabel"
                    }
                }
            }

            Text(
                text = subtitle,
                style = VdpiTextStyles.body,
                color = heroInkSecondary,
                maxLines = if (isError) 2 else 1,
                overflow = TextOverflow.Ellipsis,
            )

            // Connected 3-column translucent inset telemetry bar
            AnimatedVisibility(
                visible = isConnected,
                enter = fadeIn(tween(220)) + expandVertically(tween(240)),
                exit = fadeOut(tween(140)) + shrinkVertically(tween(180)),
            ) {
                Column {
                    Spacer(Modifier.height(18.dp))
                    HeroTelemetryBar(telemetry = snap)
                }
            }

            Spacer(Modifier.height(20.dp))

            PrimaryTunnelCtaPill(
                phase = phase,
                onClick = onToggleTunnel,
            )
        }
    }
}

@Composable
private fun HeroTelemetryBar(telemetry: TelemetrySnapshot) {
    val barShape = RoundedCornerShape(18.dp)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(barShape)
            .background(Color(0x3D000000))
            .border(1.dp, Color(0x2EFFFFFF), barShape)
            .padding(horizontal = 8.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        HeroMetricCell(
            label = "DOWNLINK",
            value = formatBytes(telemetry.bytesRx),
            modifier = Modifier.weight(1f),
        )
        Box(
            modifier = Modifier
                .width(1.dp)
                .height(28.dp)
                .background(Color(0x24FFFFFF)),
        )
        HeroMetricCell(
            label = "UPLINK",
            value = formatBytes(telemetry.bytesTx),
            modifier = Modifier.weight(1f),
        )
        Box(
            modifier = Modifier
                .width(1.dp)
                .height(28.dp)
                .background(Color(0x24FFFFFF)),
        )
        HeroMetricCell(
            label = "QUIC BLOCKED",
            value = telemetry.quicBlocked.toString(),
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun HeroMetricCell(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.padding(horizontal = 6.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = label,
            style = VdpiTextStyles.overline,
            fontSize = 9.sp,
            letterSpacing = 0.75.sp,
            color = Color(0xADFFFFFF),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text = value,
            style = VdpiTextStyles.monoMetric,
            color = Color(0xFFFFFFFF),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun PrimaryTunnelCtaPill(
    phase: TunnelPhase,
    onClick: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val interaction = remember { MutableInteractionSource() }
    val isConnected = phase == TunnelPhase.CONNECTED
    val isConnecting = phase == TunnelPhase.CONNECTING
    val isDisconnected = phase == TunnelPhase.DISCONNECTED

    val bgColor by animateColorAsState(
        targetValue = when {
            isConnected -> Color(0x2BFFFFFF)
            isDisconnected && !palette.isDark -> palette.primaryButtonBg
            else -> Color(0xFFFFFFFF)
        },
        animationSpec = tween(220),
        label = "ctaBg",
    )
    val contentColor by animateColorAsState(
        targetValue = when {
            isConnected -> Color(0xFFFFFFFF)
            isDisconnected && !palette.isDark -> palette.primaryButtonInk
            else -> Color(0xFF06080B)
        },
        animationSpec = tween(220),
        label = "ctaInk",
    )

    val borderBrush = if (isConnected) {
        Brush.verticalGradient(listOf(Color(0x8CFFFFFF), Color(0x2EFFFFFF)))
    } else {
        Brush.verticalGradient(listOf(Color.Transparent, Color.Transparent))
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(52.dp)
            .springPress(interactionSource = interaction, pressedScale = 0.96f)
            .clip(CircleShape)
            .background(bgColor)
            .border(
                width = if (isConnected) 1.dp else 0.dp,
                brush = borderBrush,
                shape = CircleShape,
            )
            .clickable(
                interactionSource = interaction,
                indication = null,
                role = Role.Button,
                onClick = onClick,
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
                    color = contentColor,
                )
                Spacer(Modifier.width(10.dp))
            }
            Text(
                text = when (phase) {
                    TunnelPhase.CONNECTED -> "Disconnect"
                    TunnelPhase.CONNECTING -> "Cancel Connection"
                    TunnelPhase.ERROR -> "Retry Connection"
                    TunnelPhase.DISCONNECTED -> "Connect"
                },
                style = VdpiTextStyles.button,
                fontWeight = FontWeight.SemiBold,
                fontSize = 15.sp,
                color = contentColor,
            )
        }
    }
}

@Composable
private fun InlineReconnectCard(onReconnect: () -> Unit) {
    val palette = VdpiThemeTokens.palette
    val interaction = remember { MutableInteractionSource() }

    LiquidGlassCard(
        modifier = Modifier.fillMaxWidth(),
        radius = 20.dp,
        rimTint = palette.warning,
        fillTint = palette.warningTint,
        elevated = false,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 16.dp, end = 12.dp, top = 12.dp, bottom = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(
                modifier = Modifier.weight(1f),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(palette.warning),
                )
                Spacer(Modifier.width(10.dp))
                Text(
                    text = "Settings changed - Reconnect to apply",
                    style = VdpiTextStyles.caption,
                    fontWeight = FontWeight.Medium,
                    color = palette.inkPrimary,
                )
            }
            Spacer(Modifier.width(10.dp))
            LiquidGlassCapsule(
                modifier = Modifier
                    .springPress(interactionSource = interaction, pressedScale = 0.95f)
                    .heightIn(min = 38.dp)
                    .clickable(
                        interactionSource = interaction,
                        indication = null,
                        role = Role.Button,
                        onClick = onReconnect,
                    ),
                rimTint = palette.warning,
                fillTint = palette.warning.copy(alpha = 0.20f),
                elevated = false,
            ) {
                Text(
                    text = "Reconnect",
                    fontFamily = GeistSans,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 12.sp,
                    color = palette.warning,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
                )
            }
        }
    }
}

@Composable
private fun LiveTelemetrySection(
    telemetry: TelemetrySnapshot,
    settings: VdpiSettings,
    isConnected: Boolean,
    cacheClearedFeedback: Boolean,
    onClearCache: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette

    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 4.dp, end = 4.dp, bottom = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            SectionOverline(text = "Live Telemetry")
            Text(
                text = "${telemetry.activeConnections} active flows",
                style = VdpiTextStyles.monoSmall,
                color = palette.inkMuted,
            )
        }

        LiquidGlassCard(
            modifier = Modifier.fillMaxWidth(),
            radius = 24.dp,
        ) {
            // Crisp 2-column throughput tiles
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(14.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                ThroughputTile(
                    label = "DOWNLINK",
                    arrow = "↓",
                    arrowColor = palette.signal,
                    value = formatBytes(telemetry.bytesRx),
                    footnote = "${telemetry.tlsHandshakes} TLS handshakes",
                    modifier = Modifier.weight(1f),
                )
                ThroughputTile(
                    label = "UPLINK",
                    arrow = "↑",
                    arrowColor = palette.accent,
                    value = formatBytes(telemetry.bytesTx),
                    footnote = "${telemetry.totalConnections} total flows",
                    modifier = Modifier.weight(1f),
                )
            }

            HairlineRule()

            LedgerRow(
                label = "ENGINE STAGE",
                primaryValue = formatStageShort(telemetry.stageNumber, telemetry.stageLabel),
                secondaryMono = "${telemetry.learnedHosts} learned",
                highlightPrimary = isConnected,
            )
            HairlineRule()
            LedgerRow(
                label = "DNS RESOLVER",
                primaryValue = "${if (settings.enableDoh) "DoH" else "UDP"} · ${settings.dnsAddr}",
                secondaryMono = if (settings.enableDoh) "Encrypted" else "Plaintext",
            )
            HairlineRule()
            LedgerRow(
                label = "ACTIVE TRAFFIC",
                primaryValue = "${telemetry.activeConnections} TCP · ${telemetry.udpFlowsActive} UDP",
                secondaryMono = "${telemetry.dnsQueries} DNS",
                primaryMono = true,
            )
            HairlineRule()
            LedgerRow(
                label = "QUIC BLOCKED",
                primaryValue = if (settings.blockQuic) {
                    "${telemetry.quicBlocked} dropped"
                } else {
                    "QUIC open"
                },
                secondaryMono = if (settings.ipv4Only) "IPv4 only" else "Dual-stack",
                primaryMono = true,
            )
            HairlineRule()

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = if (cacheClearedFeedback) "Engine cache cleared" else "Adaptive strategy cache",
                    style = VdpiTextStyles.caption,
                    color = if (cacheClearedFeedback) palette.signal else palette.inkSecondary,
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(12.dp))
                GlassActionPill(
                    label = if (cacheClearedFeedback) "Cleared" else "Clear engine cache",
                    labelColor = if (cacheClearedFeedback) palette.signal else palette.inkPrimary,
                    onClick = onClearCache,
                )
            }
        }
    }
}

@Composable
private fun ThroughputTile(
    label: String,
    arrow: String,
    arrowColor: Color,
    value: String,
    footnote: String,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    val tileShape = RoundedCornerShape(16.dp)
    val tileBg = if (palette.isDark) Color(0x14FFFFFF) else Color(0x0A0A0F1A)
    val tileBorder = if (palette.isDark) Color(0x1FFFFFFF) else palette.border

    Column(
        modifier = modifier
            .clip(tileShape)
            .background(tileBg)
            .border(1.dp, tileBorder, tileShape)
            .padding(horizontal = 14.dp, vertical = 12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = arrow,
                style = VdpiTextStyles.monoSmall,
                fontWeight = FontWeight.Medium,
                color = arrowColor,
            )
            Spacer(Modifier.width(5.dp))
            Text(
                text = label,
                style = VdpiTextStyles.overline,
                fontSize = 10.sp,
                color = palette.inkMuted,
            )
        }
        Spacer(Modifier.height(6.dp))
        Text(
            text = value,
            style = VdpiTextStyles.heroMetric,
            color = palette.inkPrimary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.height(3.dp))
        Text(
            text = footnote,
            style = VdpiTextStyles.monoSmall,
            color = palette.inkSecondary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun StandbyProfileSection(
    settings: VdpiSettings,
    cacheClearedFeedback: Boolean,
    onOpenDiagnostics: () -> Unit,
    onClearCache: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette

    Column(modifier = Modifier.fillMaxWidth()) {
        SectionOverline(
            text = "Standby Profile",
            modifier = Modifier.padding(start = 4.dp, bottom = 10.dp),
        )

        LiquidGlassCard(
            modifier = Modifier.fillMaxWidth(),
            radius = 24.dp,
        ) {
            LedgerRow(
                label = "DESYNC MODE",
                primaryValue = settings.desyncMode.label,
                secondaryMono = "${settings.chunkSize} B chunk",
            )
            HairlineRule()
            LedgerRow(
                label = "DNS RESOLVER",
                primaryValue = "${if (settings.enableDoh) "DoH" else "UDP"} · ${settings.dnsAddr}",
                secondaryMono = if (settings.enableDoh) "DoH enabled" else "UDP only",
            )
            HairlineRule()
            LedgerRow(
                label = "PROTOCOL",
                primaryValue = if (settings.blockQuic) "QUIC blocked" else "QUIC allowed",
                secondaryMono = if (settings.ipv4Only) "IPv4 only" else "Dual-stack",
            )
            HairlineRule()
            LedgerRow(
                label = "SPLIT TUNNEL",
                primaryValue = settings.splitTunnelMode.label,
                secondaryMono = splitSummary(settings) ?: "All apps",
            )
            HairlineRule()

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                GlassActionPill(
                    label = "Diagnostics",
                    onClick = onOpenDiagnostics,
                    modifier = Modifier.weight(1f),
                )
                GlassActionPill(
                    label = if (cacheClearedFeedback) "Cache cleared" else "Clear cache",
                    labelColor = if (cacheClearedFeedback) palette.signal else palette.inkPrimary,
                    onClick = onClearCache,
                    modifier = Modifier.weight(1f),
                )
            }
        }
    }
}

@Composable
private fun GlassActionPill(
    label: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    labelColor: Color = VdpiThemeTokens.palette.inkPrimary,
) {
    val interaction = remember { MutableInteractionSource() }
    LiquidGlassCapsule(
        modifier = modifier
            .springPress(interactionSource = interaction, pressedScale = 0.96f)
            .heightIn(min = 40.dp)
            .clickable(
                interactionSource = interaction,
                indication = null,
                role = Role.Button,
                onClick = onClick,
            ),
        elevated = false,
    ) {
        Text(
            text = label,
            fontFamily = GeistSans,
            fontWeight = FontWeight.Medium,
            fontSize = 12.sp,
            color = labelColor,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 9.dp),
        )
    }
}

@Composable
private fun StatusBeacon(
    color: Color,
    pulsing: Boolean,
) {
    Box(
        modifier = Modifier.size(12.dp),
        contentAlignment = Alignment.Center,
    ) {
        if (pulsing) {
            val infinite = rememberInfiniteTransition(label = "beacon")
            val pulseScale = infinite.animateFloat(
                initialValue = 1f,
                targetValue = 2.6f,
                animationSpec = infiniteRepeatable(
                    animation = tween(1800, easing = FastOutSlowInEasing),
                    repeatMode = RepeatMode.Restart,
                ),
                label = "beaconScale",
            )
            val pulseAlpha = infinite.animateFloat(
                initialValue = 0.5f,
                targetValue = 0f,
                animationSpec = infiniteRepeatable(
                    animation = tween(1800, easing = FastOutSlowInEasing),
                    repeatMode = RepeatMode.Restart,
                ),
                label = "beaconAlpha",
            )
            Box(
                modifier = Modifier
                    .size(7.dp)
                    .graphicsLayer {
                        val s = pulseScale.value
                        scaleX = s
                        scaleY = s
                        alpha = pulseAlpha.value
                    }
                    .clip(CircleShape)
                    .background(color),
            )
        }
        Box(
            modifier = Modifier
                .size(7.dp)
                .clip(CircleShape)
                .background(color),
        )
    }
}

@Composable
private fun DiagnosticsGlyph(tint: Color) {
    Canvas(modifier = Modifier.size(19.dp)) {
        val w = size.width
        val h = size.height
        val stroke = Stroke(
            width = 1.65.dp.toPx(),
            cap = StrokeCap.Round,
            join = StrokeJoin.Round,
        )
        // Tactical shield contour
        val shield = Path().apply {
            moveTo(w * 0.50f, h * 0.10f)
            lineTo(w * 0.84f, h * 0.24f)
            lineTo(w * 0.84f, h * 0.50f)
            cubicTo(w * 0.84f, h * 0.72f, w * 0.68f, h * 0.85f, w * 0.50f, h * 0.92f)
            cubicTo(w * 0.32f, h * 0.85f, w * 0.16f, h * 0.72f, w * 0.16f, h * 0.50f)
            lineTo(w * 0.16f, h * 0.24f)
            close()
        }
        drawPath(path = shield, color = tint, style = stroke)

        // Pulse waveform inside shield
        val pulse = Path().apply {
            moveTo(w * 0.29f, h * 0.52f)
            lineTo(w * 0.41f, h * 0.52f)
            lineTo(w * 0.47f, h * 0.37f)
            lineTo(w * 0.55f, h * 0.64f)
            lineTo(w * 0.61f, h * 0.52f)
            lineTo(w * 0.71f, h * 0.52f)
        }
        drawPath(path = pulse, color = tint, style = stroke)
    }
}

@Composable
private fun EngineLogGlyph(tint: Color) {
    Canvas(modifier = Modifier.size(19.dp)) {
        val w = size.width
        val h = size.height
        val strokePx = 1.65.dp.toPx()
        val stroke = Stroke(
            width = strokePx,
            cap = StrokeCap.Round,
            join = StrokeJoin.Round,
        )
        // Rounded terminal frame
        drawRoundRect(
            color = tint,
            topLeft = Offset(w * 0.12f, h * 0.16f),
            size = Size(w * 0.76f, h * 0.68f),
            cornerRadius = CornerRadius(3.5.dp.toPx(), 3.5.dp.toPx()),
            style = stroke,
        )
        // Prompt chevron ">"
        val chevron = Path().apply {
            moveTo(w * 0.28f, h * 0.38f)
            lineTo(w * 0.41f, h * 0.49f)
            lineTo(w * 0.28f, h * 0.60f)
        }
        drawPath(path = chevron, color = tint, style = stroke)
        // Log output lines
        drawLine(
            color = tint,
            start = Offset(w * 0.49f, h * 0.43f),
            end = Offset(w * 0.72f, h * 0.43f),
            strokeWidth = strokePx,
            cap = StrokeCap.Round,
        )
        drawLine(
            color = tint,
            start = Offset(w * 0.49f, h * 0.60f),
            end = Offset(w * 0.67f, h * 0.60f),
            strokeWidth = strokePx,
            cap = StrokeCap.Round,
        )
    }
}

@Composable
private fun LedgerRow(
    label: String,
    primaryValue: String,
    secondaryMono: String,
    primaryMono: Boolean = false,
    highlightPrimary: Boolean = false,
) {
    val palette = VdpiThemeTokens.palette
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 13.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = label,
                style = VdpiTextStyles.overline,
                fontSize = 10.sp,
                color = palette.inkMuted,
            )
            Spacer(Modifier.height(3.dp))
            Text(
                text = primaryValue,
                style = if (primaryMono) VdpiTextStyles.monoMetric else VdpiTextStyles.rowTitle,
                color = if (highlightPrimary) palette.signal else palette.inkPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Spacer(Modifier.width(12.dp))
        Text(
            text = secondaryMono,
            style = VdpiTextStyles.monoSmall,
            color = palette.inkSecondary,
            maxLines = 1,
        )
    }
}

@Composable
private fun DoctorSheetContent(
    doctorState: DoctorUiState,
    onRerun: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .navigationBarsPadding()
            .padding(horizontal = 20.dp)
            .padding(bottom = 24.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Diagnostics",
                    style = VdpiTextStyles.sheetTitle,
                    color = palette.inkPrimary,
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text = "Live DoH and TLS handshake verification",
                    style = VdpiTextStyles.caption,
                    color = palette.inkSecondary,
                )
            }
            Spacer(Modifier.width(12.dp))
            GhostActionButton(
                label = if (doctorState.running) "Running" else "Re-run",
                enabled = !doctorState.running,
                onClick = onRerun,
            )
        }

        Spacer(Modifier.height(16.dp))

        if (doctorState.running) {
            LiquidGlassCard(
                modifier = Modifier.fillMaxWidth(),
                radius = 20.dp,
                elevated = false,
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(20.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                        color = palette.warning,
                    )
                    Spacer(Modifier.width(12.dp))
                    Text(
                        text = "Probing encrypted DNS and TLS endpoints...",
                        style = VdpiTextStyles.body,
                        color = palette.inkSecondary,
                    )
                }
            }
        } else if (doctorState.report != null) {
            val report = doctorState.report
            val allPassed = report.ok && report.checks.all { it.passed }

            LiquidGlassCapsule(
                rimTint = if (allPassed) palette.signal else palette.danger,
                fillTint = if (allPassed) palette.signalTint else palette.dangerTint,
                elevated = false,
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Box(
                        modifier = Modifier
                            .size(7.dp)
                            .clip(CircleShape)
                            .background(if (allPassed) palette.signal else palette.danger),
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = if (allPassed) {
                            "All ${report.checks.size} checks passed"
                        } else {
                            "${report.checks.count { !it.passed }} of ${report.checks.size} checks failed"
                        },
                        style = VdpiTextStyles.monoSmall,
                        fontWeight = FontWeight.Medium,
                        color = if (allPassed) palette.signal else palette.danger,
                    )
                }
            }

            Spacer(Modifier.height(12.dp))

            LiquidGlassCard(
                modifier = Modifier.fillMaxWidth(),
                radius = 20.dp,
                elevated = false,
            ) {
                report.checks.forEachIndexed { idx, check ->
                    if (idx > 0) HairlineRule()
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .semantics(mergeDescendants = true) {
                                contentDescription =
                                    "${check.name}, ${if (check.passed) "Passed" else "Failed"}, ${check.latencyMs} ms, ${check.detail}"
                            }
                            .padding(horizontal = 16.dp, vertical = 14.dp),
                        verticalAlignment = Alignment.Top,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Row(
                            modifier = Modifier.weight(1f),
                            verticalAlignment = Alignment.Top,
                        ) {
                            Text(
                                text = if (check.passed) "PASS" else "FAIL",
                                style = VdpiTextStyles.monoSmall,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = if (check.passed) palette.signal else palette.danger,
                                modifier = Modifier
                                    .padding(top = 2.dp)
                                    .clip(RoundedCornerShape(6.dp))
                                    .background(if (check.passed) palette.signalTint else palette.dangerTint)
                                    .border(
                                        1.dp,
                                        if (check.passed) palette.signalBorder else palette.danger.copy(alpha = 0.35f),
                                        RoundedCornerShape(6.dp),
                                    )
                                    .padding(horizontal = 6.dp, vertical = 2.dp),
                            )
                            Spacer(Modifier.width(10.dp))
                            Column {
                                Text(
                                    text = check.name,
                                    style = VdpiTextStyles.rowTitle,
                                    color = palette.inkPrimary,
                                )
                                Spacer(Modifier.height(2.dp))
                                Text(
                                    text = check.detail,
                                    style = VdpiTextStyles.monoSmall,
                                    color = palette.inkSecondary,
                                    lineHeight = 16.sp,
                                )
                            }
                        }
                        Spacer(Modifier.width(10.dp))
                        Text(
                            text = "${check.latencyMs} ms",
                            style = VdpiTextStyles.monoSmall,
                            color = palette.inkMuted,
                        )
                    }
                }
            }
        } else {
            LiquidGlassCard(
                modifier = Modifier.fillMaxWidth(),
                radius = 20.dp,
                elevated = false,
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(24.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = "Tap Re-run to probe encrypted DNS and TLS",
                        style = VdpiTextStyles.caption,
                        color = palette.inkMuted,
                    )
                }
            }
        }
    }
}

@Composable
private fun EngineLogSheetContent(
    events: List<EngineEvent>,
    onClearCache: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val clipboard = LocalClipboardManager.current
    val reversed = remember(events) { events.asReversed() }
    var sheetNotice by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(sheetNotice) {
        if (sheetNotice != null) {
            delay(2200L)
            sheetNotice = null
        }
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .navigationBarsPadding()
            .padding(horizontal = 20.dp)
            .padding(bottom = 24.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Engine Log",
                    style = VdpiTextStyles.sheetTitle,
                    color = palette.inkPrimary,
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text = sheetNotice ?: "Recent events from local TUN core",
                    style = VdpiTextStyles.caption,
                    color = if (sheetNotice != null) palette.signal else palette.inkSecondary,
                )
            }
            Spacer(Modifier.width(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                GhostActionButton(
                    label = "Copy",
                    enabled = events.isNotEmpty(),
                    onClick = {
                        val dump = events.joinToString("\n") { ev ->
                            "[${formatEventTime(ev.tsMs)}] [${ev.level.uppercase()}] [${ev.tag}] ${ev.message}"
                        }
                        clipboard.setText(AnnotatedString(dump))
                        sheetNotice = "Copied ${events.size} events"
                    },
                )
                GhostActionButton(
                    label = "Reset",
                    onClick = {
                        onClearCache()
                        sheetNotice = "Adaptive cache cleared"
                    },
                )
            }
        }

        Spacer(Modifier.height(14.dp))

        LiquidGlassCard(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 180.dp, max = 380.dp),
            radius = 20.dp,
            elevated = false,
        ) {
            if (reversed.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(28.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = "No engine events yet",
                        style = VdpiTextStyles.monoSmall,
                        fontSize = 12.sp,
                        color = palette.inkMuted,
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 14.dp, vertical = 10.dp),
                ) {
                    itemsIndexed(
                        items = reversed,
                        key = { idx, ev -> if (ev.seq > 0L) ev.seq else "${ev.tsMs}-${ev.tag}-$idx" },
                    ) { idx, ev ->
                        if (idx > 0) {
                            HairlineRule(modifier = Modifier.padding(vertical = 6.dp))
                        }
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 2.dp),
                            verticalAlignment = Alignment.Top,
                        ) {
                            Text(
                                text = formatEventTime(ev.tsMs),
                                style = VdpiTextStyles.monoSmall,
                                color = palette.inkMuted,
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                text = "[${ev.tag}]",
                                style = VdpiTextStyles.monoSmall,
                                fontWeight = FontWeight.Medium,
                                color = when (ev.level) {
                                    "error" -> palette.danger
                                    "warn" -> palette.warning
                                    else -> palette.signal
                                },
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                text = ev.message,
                                fontFamily = GeistMono,
                                fontSize = 11.sp,
                                color = palette.inkPrimary,
                                lineHeight = 16.sp,
                                modifier = Modifier.weight(1f),
                            )
                        }
                    }
                }
            }
        }
    }
}

private fun splitSummary(settings: VdpiSettings): String? {
    val count = settings.splitPackages.size
    if (count == 0) return null
    return when (settings.splitTunnelMode) {
        SplitTunnelMode.BYPASS_SELECTED -> "$count bypassed"
        SplitTunnelMode.ONLY_SELECTED -> "$count routed"
    }
}
