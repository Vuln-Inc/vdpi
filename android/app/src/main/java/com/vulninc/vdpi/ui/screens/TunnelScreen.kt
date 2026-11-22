package com.vulninc.vdpi.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import androidx.compose.ui.draw.scale
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
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
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens
import com.vulninc.vdpi.util.formatBytes
import com.vulninc.vdpi.util.formatEventTime
import com.vulninc.vdpi.util.formatStageShort
import com.vulninc.vdpi.util.formatUptime
import com.vulninc.vdpi.vpn.TunnelPhase
import com.vulninc.vdpi.vpn.TunnelRuntimeSnapshot

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TunnelScreen(
    runtime: TunnelRuntimeSnapshot,
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
        // Minimal header: brand mark + wordmark + mono version badge
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
                    fontFamily = GeistMono,
                    fontSize = 11.sp,
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
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(7.dp)
                                .clip(CircleShape)
                                .background(statusDotColor),
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = when (runtime.phase) {
                                TunnelPhase.CONNECTED -> "ACTIVE · LOCAL TUN"
                                TunnelPhase.CONNECTING -> "STARTING ENGINE"
                                TunnelPhase.ERROR -> "ENGINE ERROR"
                                TunnelPhase.DISCONNECTED -> "STANDBY"
                            },
                            fontFamily = GeistMono,
                            fontWeight = FontWeight.Medium,
                            fontSize = 11.sp,
                            letterSpacing = 0.8.sp,
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
                            fontFamily = GeistMono,
                            fontWeight = FontWeight.Medium,
                            fontSize = 12.sp,
                            color = palette.inkSecondary,
                            style = androidx.compose.ui.text.TextStyle(fontFeatureSettings = "tnum"),
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
                    fontFamily = GeistSans,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 30.sp,
                    lineHeight = 34.sp,
                    letterSpacing = (-0.9).sp,
                    color = palette.inkPrimary,
                )

                Spacer(Modifier.height(6.dp))

                val subtitle = when {
                    isError && !runtime.errorMessage.isNullOrBlank() -> runtime.errorMessage
                    isConnected -> {
                        val splitNote = splitSummary(settings)
                        val modeStr = formatStageShort(
                            runtime.telemetry.stageNumber,
                            runtime.telemetry.stageLabel,
                        )
                        if (splitNote != null) "$modeStr · $splitNote" else "$modeStr · ${settings.dnsAddr}"
                    }
                    isConnecting -> "Establishing local TUN interface and DNS ring"
                    else -> "Userspace anti-DPI engine · ${settings.desyncMode.label} · ${if (settings.enableDoh) "DoH" else "UDP"} ${settings.dnsAddr}"
                }

                Text(
                    text = subtitle,
                    fontFamily = GeistSans,
                    fontSize = 13.sp,
                    lineHeight = 19.sp,
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

        AnimatedVisibility(visible = pendingReconnect && isConnected) {
            Column {
                Spacer(Modifier.height(12.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(palette.warningTint)
                        .border(1.dp, palette.warning.copy(alpha = 0.35f), RoundedCornerShape(10.dp))
                        .padding(horizontal = 14.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = "Settings updated. Reconnect to apply.",
                        fontFamily = GeistSans,
                        fontSize = 12.sp,
                        color = palette.inkPrimary,
                        modifier = Modifier.weight(1f),
                    )
                    Spacer(Modifier.width(12.dp))
                    Text(
                        text = "Reconnect",
                        fontFamily = GeistSans,
                        fontWeight = FontWeight.Medium,
                        fontSize = 12.sp,
                        color = palette.warning,
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .clickable(onClick = onReconnect)
                            .padding(horizontal = 8.dp, vertical = 4.dp),
                    )
                }
            }
        }

        Spacer(Modifier.height(22.dp))

        SectionOverline(
            text = "Telemetry",
            modifier = Modifier.padding(start = 2.dp, bottom = 8.dp),
        )

        // Single cohesive hairline ledger — zero equal-weight icon cards
        HairlinePanel(radius = 14.dp) {
            val snap = runtime.telemetry
            LedgerRow(
                label = "TLS ENGINE",
                primaryValue = if (isConnected) {
                    formatStageShort(snap.stageNumber, snap.stageLabel)
                } else {
                    "${settings.desyncMode.label} · ${settings.chunkSize}B"
                },
                secondaryMono = "${snap.learnedHosts} learned",
                highlightPrimary = isConnected,
            )
            HairlineRule()
            LedgerRow(
                label = "DNS RING",
                primaryValue = if (settings.enableDoh) {
                    "DoH · ${settings.dnsAddr}"
                } else {
                    "UDP · ${settings.dnsAddr}"
                },
                secondaryMono = "${snap.dnsQueries} queries",
            )
            HairlineRule()
            LedgerRow(
                label = "THROUGHPUT",
                primaryValue = "↓ ${formatBytes(snap.bytesRx)}   ↑ ${formatBytes(snap.bytesTx)}",
                secondaryMono = "${snap.activeConnections} active",
                primaryMono = true,
            )
            HairlineRule()
            LedgerRow(
                label = "SESSIONS",
                primaryValue = "${snap.tlsHandshakes} TLS · ${snap.udpFlowsActive} UDP",
                secondaryMono = if (settings.blockQuic) {
                    "${snap.quicBlocked} QUIC dropped"
                } else {
                    "QUIC allowed"
                },
                primaryMono = true,
            )
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
            .scale(scale)
            .clip(shape)
            .background(bgColor)
            .border(
                width = if (isConnected || isConnecting) 1.dp else 0.dp,
                color = if (isConnected || isConnecting) palette.borderStrong else androidx.compose.ui.graphics.Color.Transparent,
                shape = shape,
            )
            .clickable(
                enabled = !isConnecting,
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
                    TunnelPhase.CONNECTING -> "Starting"
                    TunnelPhase.ERROR -> "Retry connection"
                    TunnelPhase.DISCONNECTED -> "Connect"
                },
                fontFamily = GeistSans,
                fontWeight = FontWeight.Medium,
                fontSize = 14.sp,
                letterSpacing = (-0.1).sp,
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
                fontFamily = GeistMono,
                fontWeight = FontWeight.Medium,
                fontSize = 10.sp,
                letterSpacing = 0.8.sp,
                color = palette.inkMuted,
            )
            Spacer(Modifier.height(3.dp))
            Text(
                text = primaryValue,
                fontFamily = if (primaryMono) GeistMono else GeistSans,
                fontWeight = FontWeight.Medium,
                fontSize = if (primaryMono) 13.sp else 14.sp,
                color = if (highlightPrimary) palette.inkPrimary else palette.inkPrimary,
                style = androidx.compose.ui.text.TextStyle(fontFeatureSettings = "tnum"),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Spacer(Modifier.width(12.dp))
        Text(
            text = secondaryMono,
            fontFamily = GeistMono,
            fontSize = 11.sp,
            color = palette.inkSecondary,
            style = androidx.compose.ui.text.TextStyle(fontFeatureSettings = "tnum"),
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
            .padding(horizontal = 20.dp)
            .padding(bottom = 28.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column {
                Text(
                    text = "Diagnostics",
                    fontFamily = GeistSans,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 18.sp,
                    letterSpacing = (-0.3).sp,
                    color = palette.inkPrimary,
                )
                Text(
                    text = "Live DoH and 7-stage TLS ServerHello verification",
                    fontFamily = GeistSans,
                    fontSize = 12.sp,
                    color = palette.inkSecondary,
                )
            }
            GhostActionButton(
                label = if (doctorState.running) "Running" else "Re-run",
                onClick = { if (!doctorState.running) onRerun() },
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
                        text = "Probing DNS ring, Discord, and Roblox handshakes...",
                        fontFamily = GeistSans,
                        fontSize = 13.sp,
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
                            .padding(horizontal = 14.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.Top,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Row(
                            modifier = Modifier.weight(1f),
                            verticalAlignment = Alignment.Top,
                        ) {
                            Box(
                                modifier = Modifier
                                    .padding(top = 5.dp)
                                    .size(7.dp)
                                    .clip(CircleShape)
                                    .background(if (check.passed) palette.signal else palette.danger),
                            )
                            Spacer(Modifier.width(10.dp))
                            Column {
                                Text(
                                    text = check.name,
                                    fontFamily = GeistSans,
                                    fontWeight = FontWeight.Medium,
                                    fontSize = 14.sp,
                                    color = palette.inkPrimary,
                                )
                                Text(
                                    text = check.detail,
                                    fontFamily = GeistMono,
                                    fontSize = 11.sp,
                                    color = palette.inkSecondary,
                                    lineHeight = 16.sp,
                                )
                            }
                        }
                        Spacer(Modifier.width(10.dp))
                        Text(
                            text = "${check.latencyMs} ms",
                            fontFamily = GeistMono,
                            fontSize = 11.sp,
                            color = palette.inkMuted,
                            style = androidx.compose.ui.text.TextStyle(fontFeatureSettings = "tnum"),
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
    val reversed = remember(events) { events.asReversed() }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp)
            .padding(bottom = 28.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column {
                Text(
                    text = "Engine log",
                    fontFamily = GeistSans,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 18.sp,
                    letterSpacing = (-0.3).sp,
                    color = palette.inkPrimary,
                )
                Text(
                    text = "Recent events from Rust TUN core",
                    fontFamily = GeistSans,
                    fontSize = 12.sp,
                    color = palette.inkSecondary,
                )
            }
            GhostActionButton(label = "Reset cache", onClick = onClearCache)
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
                        fontFamily = GeistMono,
                        fontSize = 12.sp,
                        color = palette.inkMuted,
                    )
                }
            } else {
                LazyColumn(modifier = Modifier.padding(12.dp)) {
                    items(reversed) { ev ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.Top,
                        ) {
                            Text(
                                text = formatEventTime(ev.tsMs),
                                fontFamily = GeistMono,
                                fontSize = 11.sp,
                                color = palette.inkMuted,
                                style = androidx.compose.ui.text.TextStyle(fontFeatureSettings = "tnum"),
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                text = "[${ev.tag}]",
                                fontFamily = GeistMono,
                                fontSize = 11.sp,
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
