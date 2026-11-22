package com.vulninc.vdpi.ui.screens

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.togetherWith
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
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
import androidx.compose.ui.graphics.Color
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
import com.vulninc.vdpi.data.SplitTunnelMode
import com.vulninc.vdpi.data.VdpiSettings
import com.vulninc.vdpi.engine.EngineEvent
import com.vulninc.vdpi.ui.DoctorUiState
import com.vulninc.vdpi.ui.components.GhostActionButton
import com.vulninc.vdpi.ui.components.HairlinePanel
import com.vulninc.vdpi.ui.components.HairlineRule
import com.vulninc.vdpi.ui.components.SectionOverline
import com.vulninc.vdpi.ui.components.VdpiBrandMark
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
import kotlinx.coroutines.flow.StateFlow

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TunnelScreen(
    tunnelState: StateFlow<TunnelRuntimeSnapshot>,
    settings: VdpiSettings,
    doctorState: DoctorUiState,
    engineVersion: String,
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

    val isConnected = runtime.phase == TunnelPhase.CONNECTED
    val isConnecting = runtime.phase == TunnelPhase.CONNECTING
    val isError = runtime.phase == TunnelPhase.ERROR

    val heroBorder by animateColorAsState(
        targetValue = when (runtime.phase) {
            TunnelPhase.CONNECTED -> palette.signalBorder
            TunnelPhase.CONNECTING -> palette.warning.copy(alpha = 0.45f)
            TunnelPhase.ERROR -> palette.danger.copy(alpha = 0.5f)
            TunnelPhase.DISCONNECTED -> palette.border
        },
        animationSpec = tween(260),
        label = "heroBorder",
    )

    val statusDotColor by animateColorAsState(
        targetValue = when (runtime.phase) {
            TunnelPhase.CONNECTED -> palette.signal
            TunnelPhase.CONNECTING -> palette.warning
            TunnelPhase.ERROR -> palette.danger
            TunnelPhase.DISCONNECTED -> palette.inkMuted
        },
        animationSpec = tween(220),
        label = "statusDot",
    )

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
    ) {
        // Minimal header: fractured-V brand mark + wordmark + mono version badge
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                VdpiBrandMark(active = isConnected, size = 22.dp)
                Spacer(Modifier.width(10.dp))
                Text(
                    text = "vdpi",
                    fontFamily = GeistSans,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 18.sp,
                    letterSpacing = (-0.5).sp,
                    color = palette.inkPrimary,
                )
            }
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(palette.surface)
                    .border(1.dp, palette.border, RoundedCornerShape(6.dp))
                    .padding(horizontal = 8.dp, vertical = 4.dp),
            ) {
                Text(
                    text = "v$engineVersion",
                    style = VdpiTextStyles.monoSmall,
                    color = palette.inkMuted,
                )
            }
        }

        Spacer(Modifier.height(22.dp))

        // Primary Operate Module
        HairlinePanel(
            borderColor = heroBorder,
            backgroundColor = palette.surface,
            radius = 16.dp,
            topHighlight = true,
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        StatusBeacon(
                            color = statusDotColor,
                            pulsing = isConnected || isConnecting,
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = when (runtime.phase) {
                                TunnelPhase.CONNECTED -> "PROTECTED"
                                TunnelPhase.CONNECTING -> "STARTING"
                                TunnelPhase.ERROR -> "INTERRUPTED"
                                TunnelPhase.DISCONNECTED -> "STANDBY"
                            },
                            style = VdpiTextStyles.overline,
                            color = when (runtime.phase) {
                                TunnelPhase.CONNECTED -> palette.signal
                                TunnelPhase.CONNECTING -> palette.warning
                                TunnelPhase.ERROR -> palette.danger
                                TunnelPhase.DISCONNECTED -> palette.inkMuted
                            },
                        )
                    }

                    if (isConnected) {
                        Text(
                            text = formatUptime(runtime.telemetry.uptimeSecs),
                            style = VdpiTextStyles.monoMetric,
                            color = palette.inkSecondary,
                        )
                    }
                }

                Spacer(Modifier.height(14.dp))

                Text(
                    text = when (runtime.phase) {
                        TunnelPhase.CONNECTED -> "Protected"
                        TunnelPhase.CONNECTING -> "Connecting"
                        TunnelPhase.ERROR -> "Interrupted"
                        TunnelPhase.DISCONNECTED -> "Disconnected"
                    },
                    style = VdpiTextStyles.hero,
                    color = palette.inkPrimary,
                )

                Spacer(Modifier.height(6.dp))

                val errMsg = runtime.errorMessage
                val subtitle = when {
                    isError && !errMsg.isNullOrBlank() -> errMsg
                    isConnected -> {
                        val splitNote = splitSummary(settings)
                        val modeStr = formatStageShort(
                            runtime.telemetry.stageNumber,
                            runtime.telemetry.stageLabel,
                        )
                        if (splitNote != null) "$modeStr · $splitNote" else "$modeStr · ${settings.dnsAddr}"
                    }
                    isConnecting -> "Starting local tunnel and encrypted DNS"
                    else -> "${settings.desyncMode.label} · ${if (settings.enableDoh) "DoH" else "UDP"} ${settings.dnsAddr}"
                }

                Text(
                    text = subtitle,
                    style = VdpiTextStyles.body,
                    color = if (isError) palette.danger else palette.inkSecondary,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )

                Spacer(Modifier.height(22.dp))

                PrimaryTunnelButton(
                    phase = runtime.phase,
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        onToggleTunnel()
                    },
                )
            }
        }

        AnimatedVisibility(
            visible = pendingReconnect && isConnected,
            enter = fadeIn(tween(180)) + expandVertically(),
            exit = fadeOut(tween(140)) + shrinkVertically(),
        ) {
            Column {
                Spacer(Modifier.height(12.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(palette.warningTint)
                        .border(1.dp, palette.warning.copy(alpha = 0.35f), RoundedCornerShape(12.dp))
                        .padding(start = 14.dp, end = 8.dp, top = 6.dp, bottom = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = "Settings changed. Reconnect to apply.",
                        style = VdpiTextStyles.caption,
                        color = palette.inkPrimary,
                        modifier = Modifier.weight(1f),
                    )
                    Spacer(Modifier.width(8.dp))
                    Box(
                        modifier = Modifier
                            .heightIn(min = 44.dp)
                            .clip(RoundedCornerShape(8.dp))
                            .clickable(role = Role.Button, onClick = onReconnect)
                            .padding(horizontal = 12.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = "Reconnect",
                            fontFamily = GeistSans,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 12.sp,
                            color = palette.warning,
                        )
                    }
                }
            }
        }

        Spacer(Modifier.height(22.dp))

        // Smooth crossfade between quiet Active Profile on standby and Live Telemetry when active
        AnimatedContent(
            targetState = isConnected || isConnecting,
            transitionSpec = {
                fadeIn(tween(180)) togetherWith fadeOut(tween(120))
            },
            label = "telemetryPanelTransition",
        ) { live ->
            if (!live) {
                Column {
                    SectionOverline(
                        text = "Active Profile",
                        modifier = Modifier.padding(start = 2.dp, bottom = 8.dp),
                    )
                    HairlinePanel(radius = 14.dp) {
                        LedgerRow(
                            label = "ENGINE",
                            primaryValue = "${settings.desyncMode.label} · ${settings.chunkSize} B",
                            secondaryMono = if (settings.blockQuic) "QUIC blocked" else "QUIC open",
                        )
                        HairlineRule()
                        LedgerRow(
                            label = "DNS",
                            primaryValue = "${if (settings.enableDoh) "DoH" else "UDP"} · ${settings.dnsAddr}",
                            secondaryMono = if (settings.ipv4Only) "IPv4 only" else "Dual-stack",
                        )
                        HairlineRule()
                        LedgerRow(
                            label = "SPLIT TUNNEL",
                            primaryValue = settings.splitTunnelMode.label,
                            secondaryMono = splitSummary(settings) ?: "All apps",
                        )
                    }
                }
            } else {
                Column {
                    SectionOverline(
                        text = "Live Telemetry",
                        modifier = Modifier.padding(start = 2.dp, bottom = 8.dp),
                    )
                    HairlinePanel(radius = 14.dp) {
                        val snap = runtime.telemetry
                        LedgerRow(
                            label = "TLS ENGINE",
                            primaryValue = formatStageShort(snap.stageNumber, snap.stageLabel),
                            secondaryMono = "${snap.learnedHosts} learned",
                            highlightPrimary = isConnected,
                        )
                        HairlineRule()
                        LedgerRow(
                            label = "DNS RESOLVER",
                            primaryValue = "${if (settings.enableDoh) "DoH" else "UDP"} · ${settings.dnsAddr}",
                            secondaryMono = "${snap.dnsQueries} queries",
                        )
                        HairlineRule()
                        ThroughputLedgerRow(
                            rxText = formatBytes(snap.bytesRx),
                            txText = formatBytes(snap.bytesTx),
                            activeConnections = snap.activeConnections,
                        )
                        HairlineRule()
                        LedgerRow(
                            label = "SESSIONS",
                            primaryValue = "${snap.tlsHandshakes} TLS · ${snap.udpFlowsActive} UDP",
                            secondaryMono = if (settings.blockQuic) {
                                "${snap.quicBlocked} QUIC dropped"
                            } else {
                                "QUIC open"
                            },
                            primaryMono = true,
                        )
                    }
                }
            }
        }

        Spacer(Modifier.height(14.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            GhostActionButton(
                label = "Diagnostics",
                onClick = {
                    showDoctorSheet = true
                    if (doctorState.report == null && !doctorState.running) {
                        onRunDoctor()
                    }
                },
                modifier = Modifier.weight(1f),
            )
            GhostActionButton(
                label = "Engine log",
                trailingMono = if (runtime.telemetry.events.isNotEmpty()) {
                    runtime.telemetry.events.size.toString()
                } else {
                    null
                },
                onClick = { showLogSheet = true },
                modifier = Modifier.weight(1f),
            )
        }

        Spacer(Modifier.height(18.dp))
    }

    if (showDoctorSheet) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(
            onDismissRequest = { showDoctorSheet = false },
            sheetState = sheetState,
            containerColor = palette.surface,
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
            containerColor = palette.surface,
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
                initialValue = 0.45f,
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
private fun PrimaryTunnelButton(
    phase: TunnelPhase,
    onClick: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val scale by animateFloatAsState(
        targetValue = if (pressed) 0.985f else 1f,
        animationSpec = spring(stiffness = Spring.StiffnessMedium),
        label = "btnScale",
    )

    val isConnected = phase == TunnelPhase.CONNECTED
    val isConnecting = phase == TunnelPhase.CONNECTING
    val shape = RoundedCornerShape(10.dp)

    val bgColor by animateColorAsState(
        targetValue = when {
            isConnected || isConnecting -> palette.surfaceRaised
            else -> palette.primaryButtonBg
        },
        animationSpec = tween(200),
        label = "btnBg",
    )
    val textColor by animateColorAsState(
        targetValue = when {
            isConnected || isConnecting -> palette.inkPrimary
            else -> palette.primaryButtonInk
        },
        animationSpec = tween(200),
        label = "btnInk",
    )

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(50.dp)
            .graphicsLayer {
                scaleX = scale
                scaleY = scale
            }
            .clip(shape)
            .background(bgColor)
            .border(
                width = 1.dp,
                color = if (isConnected || isConnecting) palette.borderStrong else Color.Transparent,
                shape = shape,
            )
            .clickable(
                enabled = true,
                role = Role.Button,
                interactionSource = interaction,
                indication = null,
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
                    modifier = Modifier.size(15.dp),
                    strokeWidth = 1.8.dp,
                    color = palette.inkSecondary,
                )
                Spacer(Modifier.width(10.dp))
            }
            Text(
                text = when (phase) {
                    TunnelPhase.CONNECTED -> "Disconnect"
                    TunnelPhase.CONNECTING -> "Cancel connection"
                    TunnelPhase.ERROR -> "Retry connection"
                    TunnelPhase.DISCONNECTED -> "Connect"
                },
                style = VdpiTextStyles.button,
                color = textColor,
            )
        }
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
        )
    }
}

@Composable
private fun ThroughputLedgerRow(
    rxText: String,
    txText: String,
    activeConnections: Int,
) {
    val palette = VdpiThemeTokens.palette
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 13.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = "DOWNLOAD",
                style = VdpiTextStyles.overline,
                fontSize = 10.sp,
                color = palette.inkMuted,
            )
            Spacer(Modifier.height(3.dp))
            Text(
                text = "↓ $rxText",
                style = VdpiTextStyles.monoMetric,
                color = palette.inkPrimary,
                maxLines = 1,
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = "UPLOAD",
                style = VdpiTextStyles.overline,
                fontSize = 10.sp,
                color = palette.inkMuted,
            )
            Spacer(Modifier.height(3.dp))
            Text(
                text = "↑ $txText",
                style = VdpiTextStyles.monoMetric,
                color = palette.inkPrimary,
                maxLines = 1,
            )
        }
        Text(
            text = "$activeConnections active",
            style = VdpiTextStyles.monoSmall,
            color = palette.inkSecondary,
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
            HairlinePanel(radius = 12.dp) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(20.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        strokeWidth = 1.8.dp,
                        color = palette.inkPrimary,
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
            HairlinePanel(radius = 12.dp) {
                report.checks.forEachIndexed { idx, check ->
                    if (idx > 0) HairlineRule()
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .semantics(mergeDescendants = true) {
                                contentDescription = "${check.name}, ${if (check.passed) "Passed" else "Failed"}, ${check.latencyMs} ms, ${check.detail}"
                            }
                            .padding(horizontal = 14.dp, vertical = 12.dp),
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
                                    .clip(RoundedCornerShape(4.dp))
                                    .background(if (check.passed) palette.signalTint else palette.dangerTint)
                                    .padding(horizontal = 5.dp, vertical = 2.dp),
                            )
                            Spacer(Modifier.width(10.dp))
                            Column {
                                Text(
                                    text = check.name,
                                    style = VdpiTextStyles.rowTitle,
                                    color = palette.inkPrimary,
                                )
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
            kotlinx.coroutines.delay(2200L)
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
                    text = "Engine log",
                    style = VdpiTextStyles.sheetTitle,
                    color = palette.inkPrimary,
                )
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
                        sheetNotice = "Copied to clipboard"
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

        HairlinePanel(
            backgroundColor = palette.canvas,
            radius = 12.dp,
            modifier = Modifier.heightIn(min = 160.dp, max = 380.dp),
        ) {
            if (reversed.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(24.dp),
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
                LazyColumn(modifier = Modifier.padding(12.dp)) {
                    itemsIndexed(
                        items = reversed,
                        key = { idx, ev -> if (ev.seq > 0L) ev.seq else "${ev.tsMs}-${ev.tag}-$idx" },
                    ) { _, ev ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp),
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
