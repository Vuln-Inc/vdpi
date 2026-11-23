package com.vulninc.vdpi.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.res.Configuration
import android.os.Build
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
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
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
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
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
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.DialogWindowProvider
import androidx.core.view.WindowCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.vulninc.vdpi.BuildConfig
import com.vulninc.vdpi.data.SplitTunnelMode
import com.vulninc.vdpi.data.VdpiSettings
import com.vulninc.vdpi.engine.EngineEvent
import com.vulninc.vdpi.engine.TelemetrySnapshot
import com.vulninc.vdpi.ui.DoctorUiState
import com.vulninc.vdpi.ui.components.FloatingGlassIconButton
import com.vulninc.vdpi.ui.components.HairlineRule
import com.vulninc.vdpi.ui.components.InsetGroupedCard
import com.vulninc.vdpi.ui.components.InsetGroupedRow
import com.vulninc.vdpi.ui.components.LocalBottomChromePadding
import com.vulninc.vdpi.ui.components.LocalReduceMotion
import com.vulninc.vdpi.ui.components.LocalTopOverlayPadding
import com.vulninc.vdpi.ui.components.SectionFooter
import com.vulninc.vdpi.ui.components.SectionOverline
import com.vulninc.vdpi.ui.components.springPress
import com.vulninc.vdpi.ui.theme.GeistMono
import com.vulninc.vdpi.ui.theme.GeistSans
import com.vulninc.vdpi.ui.theme.VdpiTextStyles
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens
import com.vulninc.vdpi.util.formatBytes
import com.vulninc.vdpi.util.formatEventTime
import com.vulninc.vdpi.util.formatStageLabel
import com.vulninc.vdpi.util.formatUptime
import com.vulninc.vdpi.vpn.TunnelPhase
import com.vulninc.vdpi.vpn.TunnelRuntimeSnapshot
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
import java.util.Locale

private val DarkLogWellBackground = Color(0xFF0D0D0F)

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

    val configuration = LocalConfiguration.current
    val isLandscape = configuration.orientation == Configuration.ORIENTATION_LANDSCAPE &&
        configuration.screenWidthDp >= 560
    val topOverlayPadding = LocalTopOverlayPadding.current
    val bottomChromePadding = LocalBottomChromePadding.current

    if (isLandscape) {
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

                // Compact top header row for landscape
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 6.dp, bottom = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = "vdpi",
                        style = VdpiTextStyles.pageTitle.copy(
                            fontSize = 24.sp,
                            lineHeight = 28.sp,
                            letterSpacing = (-0.3).sp,
                        ),
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
                            onClick = openDiagnostics,
                            contentDescription = "Diagnostics",
                            size = 38.dp,
                            badgeColor = doctorBadgeColor,
                        ) {
                            DiagnosticsGlyph(tint = palette.inkPrimary)
                        }

                        FloatingGlassIconButton(
                            onClick = openLogs,
                            contentDescription = "Engine logs",
                            size = 38.dp,
                            badgeColor = if (hasLogAlert) palette.danger else null,
                        ) {
                            EngineLogGlyph(tint = palette.inkPrimary)
                        }
                    }
                }

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
                            onToggleTunnel = {
                                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                onToggleTunnel()
                            },
                        )

                        AnimatedVisibility(
                            visible = pendingReconnect && isConnected,
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
                                Spacer(Modifier.height(10.dp))
                                InlineReconnectRow(
                                    compact = true,
                                    onReconnect = {
                                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                        onReconnect()
                                    },
                                )
                            }
                        }
                    }

                    // Right pane: Live Telemetry or Standby Profile beside the Hero Card
                    Box(modifier = Modifier.weight(0.54f)) {
                        AnimatedContent(
                            targetState = isConnected,
                            transitionSpec = {
                                fadeIn(tween(180)) togetherWith fadeOut(tween(130))
                            },
                            label = "tunnelDetailsTransitionLandscape",
                        ) { live ->
                            if (live) {
                                LiveTelemetrySection(
                                    telemetry = runtime.telemetry,
                                    settings = settings,
                                )
                            } else {
                                StandbyProfileSection(
                                    settings = settings,
                                )
                            }
                        }
                    }
                }

                Spacer(Modifier.height(bottomChromePadding + 8.dp))
            }
        }
    } else {
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

            // Clean Apple Large Title header with two calm monochrome Liquid Glass action circles
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = "vdpi",
                    style = VdpiTextStyles.pageTitle,
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
                        onClick = openDiagnostics,
                        contentDescription = "Diagnostics",
                        size = 42.dp,
                        badgeColor = doctorBadgeColor,
                    ) {
                        DiagnosticsGlyph(tint = palette.inkPrimary)
                    }

                    FloatingGlassIconButton(
                        onClick = openLogs,
                        contentDescription = "Engine logs",
                        size = 42.dp,
                        badgeColor = if (hasLogAlert) palette.danger else null,
                    ) {
                        EngineLogGlyph(tint = palette.inkPrimary)
                    }
                }
            }

            Spacer(Modifier.height(16.dp))

            // Serene opaque Apple Hero Card
            TunnelHeroCard(
                runtime = runtime,
                settings = settings,
                reduceMotion = reduceMotion,
                onToggleTunnel = {
                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                    onToggleTunnel()
                },
            )

            // Persistent inline reconnect row when settings changed during an active tunnel
            AnimatedVisibility(
                visible = pendingReconnect && isConnected,
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
                    Spacer(Modifier.height(12.dp))
                    InlineReconnectRow(
                        onReconnect = {
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            onReconnect()
                        },
                    )
                }
            }

            Spacer(Modifier.height(24.dp))

            // Inset Grouped Telemetry or Standby Profile
            AnimatedContent(
                targetState = isConnected,
                transitionSpec = {
                    fadeIn(tween(180)) togetherWith fadeOut(tween(130))
                },
                label = "tunnelDetailsTransition",
            ) { live ->
                if (live) {
                    LiveTelemetrySection(
                        telemetry = runtime.telemetry,
                        settings = settings,
                    )
                } else {
                    StandbyProfileSection(
                        settings = settings,
                    )
                }
            }

            Spacer(Modifier.height(24.dp))
            Spacer(Modifier.height(bottomChromePadding))
        }
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

@Composable
private fun SyncModalSheetSystemBars(isDark: Boolean) {
    val view = LocalView.current
    SideEffect {
        val window = (view.parent as? DialogWindowProvider)?.window ?: return@SideEffect
        WindowCompat.getInsetsController(window, view).apply {
            isAppearanceLightNavigationBars = !isDark
            isAppearanceLightStatusBars = !isDark
        }
        @Suppress("DEPRECATION")
        window.navigationBarColor = android.graphics.Color.TRANSPARENT
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            window.isNavigationBarContrastEnforced = false
        }
    }
}

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

@Composable
private fun SheetGrabber(compact: Boolean = false) {
    val palette = VdpiThemeTokens.palette
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(
                top = if (compact) 6.dp else 10.dp,
                bottom = if (compact) 4.dp else 6.dp,
            ),
        contentAlignment = Alignment.Center,
    ) {
        Box(
            modifier = Modifier
                .size(width = 36.dp, height = 5.dp)
                .clip(CircleShape)
                .background(palette.inkMuted.copy(alpha = 0.45f)),
        )
    }
}

@Composable
private fun SheetTextButton(
    label: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    emphasized: Boolean = false,
    enabled: Boolean = true,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val interaction = remember { MutableInteractionSource() }

    Box(
        modifier = modifier
            .widthIn(min = 44.dp)
            .heightIn(min = 44.dp)
            .alpha(if (enabled) 1f else 0.4f)
            .clickable(
                interactionSource = interaction,
                indication = null,
                enabled = enabled,
                role = Role.Button,
            ) {
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                onClick()
            }
            .padding(horizontal = 4.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = label,
            fontFamily = GeistSans,
            fontWeight = if (emphasized) FontWeight.SemiBold else FontWeight.Normal,
            fontSize = 16.sp,
            color = palette.accent,
            maxLines = 1,
        )
    }
}

@Composable
private fun DoctorSheetContent(
    doctorState: DoctorUiState,
    isLandscape: Boolean,
    onRerun: () -> Unit,
    onDismiss: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val cardBackground = if (palette.isDark) palette.surfaceRaised else palette.surface
    val report = doctorState.report

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .then(
                if (isLandscape) {
                    Modifier.windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal))
                } else {
                    Modifier
                },
            )
            .verticalScroll(rememberScrollState()),
        contentAlignment = Alignment.TopCenter,
    ) {
        Column(
            modifier = Modifier
                .then(if (isLandscape) Modifier.widthIn(max = 580.dp) else Modifier)
                .fillMaxWidth()
                .then(
                    if (isLandscape) {
                        Modifier.windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Bottom))
                    } else {
                        Modifier.navigationBarsPadding()
                    },
                )
                .padding(horizontal = 16.dp)
                .padding(bottom = if (isLandscape) 14.dp else 24.dp),
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 44.dp),
            ) {
                SheetTextButton(
                    label = "Re-run",
                    enabled = !doctorState.running,
                    onClick = onRerun,
                    modifier = Modifier.align(Alignment.CenterStart),
                )
                Text(
                    text = "Diagnostics",
                    style = VdpiTextStyles.sheetTitle,
                    color = palette.inkPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.align(Alignment.Center),
                )
                SheetTextButton(
                    label = "Done",
                    emphasized = true,
                    onClick = onDismiss,
                    modifier = Modifier.align(Alignment.CenterEnd),
                )
            }

            Spacer(Modifier.height(if (isLandscape) 8.dp else 14.dp))

            SectionOverline(text = "Checks")

            InsetGroupedCard(
                modifier = Modifier.fillMaxWidth(),
                radius = 16.dp,
                backgroundColor = cardBackground,
            ) {
                when {
                    doctorState.running -> {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(min = if (isLandscape) 46.dp else 54.dp)
                                .padding(
                                    horizontal = 16.dp,
                                    vertical = if (isLandscape) 10.dp else 14.dp,
                                ),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(18.dp),
                                strokeWidth = 2.dp,
                                color = palette.inkSecondary,
                            )
                            Spacer(Modifier.width(12.dp))
                            Text(
                                text = "Verifying DNS, DoH, and TLS connectivity...",
                                style = VdpiTextStyles.body,
                                color = palette.inkSecondary,
                            )
                        }
                    }

                    report != null && report.checks.isNotEmpty() -> {
                        val checks = report.checks
                        checks.forEachIndexed { idx, check ->
                            if (idx > 0) {
                                HairlineRule(startIndent = 48.dp)
                            }
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .heightIn(min = if (isLandscape) 44.dp else 50.dp)
                                    .semantics(mergeDescendants = true) {
                                        contentDescription =
                                            "${check.name}, ${if (check.passed) "Passed" else "Failed"}, ${check.latencyMs} ms, ${check.detail}"
                                    }
                                    .padding(
                                        horizontal = 16.dp,
                                        vertical = if (isLandscape) 9.dp else 12.dp,
                                    ),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                if (check.passed) {
                                    CheckCircleGlyph(tint = palette.signal)
                                } else {
                                    CrossCircleGlyph(tint = palette.danger)
                                }

                                Spacer(Modifier.width(12.dp))

                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = check.name,
                                        style = VdpiTextStyles.rowTitle,
                                        color = palette.inkPrimary,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                    if (check.detail.isNotBlank()) {
                                        Spacer(Modifier.height(2.dp))
                                        Text(
                                            text = check.detail,
                                            style = VdpiTextStyles.caption,
                                            color = palette.inkSecondary,
                                            maxLines = 2,
                                            overflow = TextOverflow.Ellipsis,
                                        )
                                    }
                                }

                                Spacer(Modifier.width(12.dp))

                                Text(
                                    text = "${check.latencyMs} ms",
                                    style = VdpiTextStyles.caption.copy(fontFeatureSettings = "tnum"),
                                    color = palette.inkSecondary,
                                    maxLines = 1,
                                )
                            }
                        }
                    }

                    report != null -> {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(
                                    horizontal = 16.dp,
                                    vertical = if (isLandscape) 14.dp else 20.dp,
                                ),
                            contentAlignment = Alignment.Center,
                        ) {
                            Text(
                                text = "No diagnostic checks were returned. Tap Re-run to try again.",
                                style = VdpiTextStyles.body,
                                color = palette.inkSecondary,
                                textAlign = TextAlign.Center,
                            )
                        }
                    }

                    else -> {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(
                                    horizontal = 16.dp,
                                    vertical = if (isLandscape) 14.dp else 20.dp,
                                ),
                            contentAlignment = Alignment.Center,
                        ) {
                            Text(
                                text = "Tap Re-run to verify DNS, DoH, and TLS endpoints.",
                                style = VdpiTextStyles.body,
                                color = palette.inkSecondary,
                                textAlign = TextAlign.Center,
                            )
                        }
                    }
                }
            }

            if (!doctorState.running && report != null && report.checks.isNotEmpty()) {
                val failedCount = report.checks.count { !it.passed }
                val footerText = if (report.ok && failedCount == 0) {
                    "All ${report.checks.size} checks passed"
                } else {
                    val noun = if (failedCount == 1) "issue" else "issues"
                    "$failedCount $noun detected - check DNS or network settings"
                }
                SectionFooter(text = footerText)
            }
        }
    }
}

@Composable
private fun EngineLogSheetContent(
    events: List<EngineEvent>,
    isLandscape: Boolean,
    onDismiss: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val context = LocalContext.current
    val listState = rememberLazyListState()
    var copiedFeedback by remember { mutableStateOf(false) }
    var copyTick by remember { mutableIntStateOf(0) }

    LaunchedEffect(copyTick) {
        if (copyTick > 0) {
            delay(1800L)
            copiedFeedback = false
        }
    }

    LaunchedEffect(events.size) {
        if (events.isNotEmpty()) {
            val lastVisible = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index
            val nearBottom = lastVisible == null || lastVisible >= (events.size - 3).coerceAtLeast(0)
            if (nearBottom) {
                listState.scrollToItem(events.lastIndex)
            }
        }
    }

    val logWellBackground = if (palette.isDark) DarkLogWellBackground else palette.surface

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .then(
                if (isLandscape) {
                    Modifier.windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal))
                } else {
                    Modifier
                },
            ),
        contentAlignment = Alignment.TopCenter,
    ) {
        Column(
            modifier = Modifier
                .then(if (isLandscape) Modifier.widthIn(max = 580.dp) else Modifier)
                .fillMaxWidth()
                .then(
                    if (isLandscape) {
                        Modifier.windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Bottom))
                    } else {
                        Modifier.navigationBarsPadding()
                    },
                )
                .padding(horizontal = 16.dp)
                .padding(bottom = if (isLandscape) 14.dp else 24.dp),
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 44.dp),
            ) {
                SheetTextButton(
                    label = if (copiedFeedback) "Copied" else "Copy",
                    enabled = events.isNotEmpty(),
                    onClick = {
                        val dump = events.joinToString("\n") { ev ->
                            val level = formatLogLevelTag(ev.level)
                            "${formatEventTime(ev.tsMs)} $level [${ev.tag}] ${ev.message}"
                        }
                        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                        cm?.setPrimaryClip(ClipData.newPlainText("vdpi engine logs", dump))
                        copiedFeedback = true
                        copyTick++
                    },
                    modifier = Modifier.align(Alignment.CenterStart),
                )
                Text(
                    text = "Engine Logs",
                    style = VdpiTextStyles.sheetTitle,
                    color = palette.inkPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.align(Alignment.Center),
                )
                SheetTextButton(
                    label = "Done",
                    emphasized = true,
                    onClick = onDismiss,
                    modifier = Modifier.align(Alignment.CenterEnd),
                )
            }

            Spacer(Modifier.height(if (isLandscape) 8.dp else 12.dp))

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f, fill = false)
                    .heightIn(
                        min = if (isLandscape) 100.dp else 140.dp,
                        max = if (isLandscape) 220.dp else 380.dp,
                    )
                    .clip(RoundedCornerShape(14.dp))
                    .background(logWellBackground)
                    .padding(if (isLandscape) 10.dp else 12.dp),
            ) {
                if (events.isEmpty()) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .align(Alignment.Center)
                            .verticalScroll(rememberScrollState())
                            .padding(
                                vertical = if (isLandscape) 14.dp else 24.dp,
                                horizontal = 16.dp,
                            ),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Text(
                            text = "No Engine Logs Yet",
                            style = VdpiTextStyles.rowTitle.copy(fontWeight = FontWeight.Medium),
                            color = palette.inkPrimary,
                            textAlign = TextAlign.Center,
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = "Connect the tunnel to record activity.",
                            style = VdpiTextStyles.caption,
                            color = palette.inkSecondary,
                            textAlign = TextAlign.Center,
                        )
                    }
                } else {
                    LazyColumn(
                        state = listState,
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        itemsIndexed(
                            items = events,
                            key = { idx, ev -> if (ev.seq > 0L) ev.seq else "${ev.tsMs}-${ev.tag}-$idx" },
                        ) { _, ev ->
                            val levelTag = formatLogLevelTag(ev.level)
                            val levelColor = when (ev.level.lowercase(Locale.ROOT)) {
                                "error", "err" -> palette.danger
                                "warn", "warning" -> palette.warning
                                else -> palette.inkSecondary
                            }
                            val line = remember(ev, levelColor, palette.inkMuted, palette.inkPrimary) {
                                buildAnnotatedString {
                                    withStyle(SpanStyle(color = palette.inkMuted)) {
                                        append(formatEventTime(ev.tsMs))
                                        append(' ')
                                    }
                                    withStyle(SpanStyle(color = levelColor, fontWeight = FontWeight.Medium)) {
                                        append(levelTag)
                                        append(' ')
                                    }
                                    withStyle(SpanStyle(color = palette.inkPrimary)) {
                                        append('[')
                                        append(ev.tag)
                                        append("] ")
                                        append(ev.message)
                                    }
                                }
                            }
                            Text(
                                text = line,
                                style = VdpiTextStyles.monoSmall.copy(
                                    fontFamily = GeistMono,
                                    fontSize = 12.sp,
                                    lineHeight = 18.sp,
                                    fontFeatureSettings = "tnum",
                                ),
                            )
                        }
                    }
                }
            }
        }
    }
}

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

@Composable
private fun CheckCircleGlyph(tint: Color) {
    val checkColor = if (VdpiThemeTokens.palette.isDark) Color(0xFF000000) else Color.White
    Canvas(modifier = Modifier.size(20.dp)) {
        val w = size.width
        val h = size.height
        drawCircle(color = tint, radius = size.minDimension * 0.46f)
        val check = Path().apply {
            moveTo(w * 0.30f, h * 0.52f)
            lineTo(w * 0.44f, h * 0.66f)
            lineTo(w * 0.71f, h * 0.36f)
        }
        drawPath(
            path = check,
            color = checkColor,
            style = Stroke(width = 1.9.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round),
        )
    }
}

@Composable
private fun CrossCircleGlyph(tint: Color) {
    Canvas(modifier = Modifier.size(20.dp)) {
        val w = size.width
        val h = size.height
        val strokePx = 1.9.dp.toPx()
        drawCircle(color = tint, radius = size.minDimension * 0.46f)
        drawLine(
            color = Color.White,
            start = Offset(w * 0.34f, h * 0.34f),
            end = Offset(w * 0.66f, h * 0.66f),
            strokeWidth = strokePx,
            cap = StrokeCap.Round,
        )
        drawLine(
            color = Color.White,
            start = Offset(w * 0.66f, h * 0.34f),
            end = Offset(w * 0.34f, h * 0.66f),
            strokeWidth = strokePx,
            cap = StrokeCap.Round,
        )
    }
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

private fun formatDnsDetail(settings: VdpiSettings): String {
    val addr = settings.dnsAddr.trim().ifBlank { "1.1.1.1" }
    val proto = if (settings.enableDoh) "DoH" else "UDP"
    return "$addr · $proto"
}

private fun isAlertLogLevel(level: String): Boolean =
    level.equals("error", ignoreCase = true) ||
        level.equals("err", ignoreCase = true) ||
        level.equals("warn", ignoreCase = true) ||
        level.equals("warning", ignoreCase = true)

private fun formatLogLevelTag(level: String): String = when (level.lowercase(Locale.ROOT)) {
    "error", "err" -> "[ERR]"
    "warn", "warning" -> "[WARN]"
    else -> "[INFO]"
}

private fun splitSummary(settings: VdpiSettings): String? {
    val count = settings.splitPackages.size
    if (count == 0) return null
    return when (settings.splitTunnelMode) {
        SplitTunnelMode.BYPASS_SELECTED -> "$count Bypassed"
        SplitTunnelMode.ONLY_SELECTED -> "$count Routed"
    }
}
