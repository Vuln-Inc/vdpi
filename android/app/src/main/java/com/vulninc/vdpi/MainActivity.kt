package com.vulninc.vdpi

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color as AndroidColor
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.Crossfade
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
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectVerticalDragGestures
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.displayCutoutPadding
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.union
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.compositeOver
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.layer.drawLayer
import androidx.compose.ui.graphics.rememberGraphicsLayer
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.vulninc.vdpi.ui.VdpiViewModel
import com.vulninc.vdpi.ui.components.AmbientCanvasBackdrop
import com.vulninc.vdpi.ui.components.FloatingGlassIconButton
import com.vulninc.vdpi.ui.components.LiquidGlassCapsule
import com.vulninc.vdpi.ui.components.LocalBottomChromePadding
import com.vulninc.vdpi.ui.components.LocalGlassBackdropLayer
import com.vulninc.vdpi.ui.components.LocalTopOverlayPadding
import com.vulninc.vdpi.ui.components.MinimalSnackbarHost
import com.vulninc.vdpi.ui.components.MinimalTabIcon
import com.vulninc.vdpi.ui.components.TabIconKind
import com.vulninc.vdpi.ui.components.VdpiMotion
import com.vulninc.vdpi.ui.components.springPress
import com.vulninc.vdpi.ui.screens.AppsScreen
import com.vulninc.vdpi.ui.screens.SettingsScreen
import com.vulninc.vdpi.ui.screens.TunnelScreen
import com.vulninc.vdpi.ui.theme.GeistSans
import com.vulninc.vdpi.ui.theme.VdpiTextStyles
import com.vulninc.vdpi.ui.theme.VdpiTheme
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens
import com.vulninc.vdpi.util.formatBytes
import com.vulninc.vdpi.util.formatUptime
import com.vulninc.vdpi.vpn.TunnelPhase
import com.vulninc.vdpi.vpn.TunnelRuntimeSnapshot
import com.vulninc.vdpi.vpn.VdpiVpnService
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlin.math.abs
import kotlin.math.roundToInt

private enum class MainTab(val label: String, val icon: TabIconKind) {
    TUNNEL("Tunnel", TabIconKind.TUNNEL),
    APPS("Apps", TabIconKind.APPS),
    SETTINGS("Settings", TabIconKind.SETTINGS),
}

private data class UiFeedbackEvent(
    val message: String,
    val actionLabel: String? = null,
    val duration: SnackbarDuration = SnackbarDuration.Short,
    val onAction: (() -> Unit)? = null,
)

class MainActivity : ComponentActivity() {

    private val viewModel: VdpiViewModel by viewModels()
    private val uiFeedback = MutableSharedFlow<UiFeedbackEvent>(extraBufferCapacity = 4)
    private var notificationPermissionRequestedThisSession = false

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnServiceWithPermissions()
        } else {
            uiFeedback.tryEmit(UiFeedbackEvent(message = "VPN permission was denied"))
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (!granted) {
            uiFeedback.tryEmit(
                UiFeedbackEvent(
                    message = getString(R.string.notification_permission_hint),
                    actionLabel = getString(R.string.notification_settings_action),
                    duration = SnackbarDuration.Long,
                    onAction = ::openAppNotificationSettings,
                ),
            )
        }
        // Re-verify VPN consent before calling startForegroundService() in case it was revoked while dialog was open.
        if (VpnService.prepare(this) == null) {
            VdpiVpnService.start(this)
        } else {
            uiFeedback.tryEmit(UiFeedbackEvent(message = "VPN permission required"))
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        notificationPermissionRequestedThisSession =
            savedInstanceState?.getBoolean(KEY_NOTIF_PERMISSION_REQUESTED, false) ?: false

        if (savedInstanceState == null && intent?.getBooleanExtra(EXTRA_AUTO_CONNECT, false) == true) {
            intent?.removeExtra(EXTRA_AUTO_CONNECT)
            requestConnect()
        }

        setContent {
            val settings by viewModel.settings.collectAsStateWithLifecycle()
            val apps by viewModel.installedApps.collectAsStateWithLifecycle()
            val appsLoading by viewModel.appsLoading.collectAsStateWithLifecycle()
            val doctorState by viewModel.doctorState.collectAsStateWithLifecycle()
            val tunnelPhase by viewModel.tunnelPhase.collectAsStateWithLifecycle()
            val pendingReconnect by viewModel.pendingReconnect.collectAsStateWithLifecycle()
            val reconnectPopupVisible by viewModel.reconnectPopupVisible.collectAsStateWithLifecycle()
            val pendingChangeSummary by viewModel.pendingChangeSummary.collectAsStateWithLifecycle()

            VdpiTheme(preference = settings.theme) {
                val palette = VdpiThemeTokens.palette
                val snackbarHostState = remember { SnackbarHostState() }
                val uiScope = rememberCoroutineScope()

                LaunchedEffect(palette.isDark) {
                    val barStyle = if (palette.isDark) {
                        SystemBarStyle.dark(AndroidColor.TRANSPARENT)
                    } else {
                        SystemBarStyle.light(AndroidColor.TRANSPARENT, AndroidColor.TRANSPARENT)
                    }
                    enableEdgeToEdge(statusBarStyle = barStyle, navigationBarStyle = barStyle)
                }

                LaunchedEffect(Unit) {
                    uiFeedback.collect { event ->
                        snackbarHostState.currentSnackbarData?.dismiss()
                        val result = snackbarHostState.showSnackbar(
                            message = event.message,
                            actionLabel = event.actionLabel,
                            duration = event.duration,
                        )
                        if (result == SnackbarResult.ActionPerformed) {
                            event.onAction?.invoke()
                        }
                    }
                }

                fun showNotice(message: String) {
                    uiScope.launch {
                        snackbarHostState.currentSnackbarData?.dismiss()
                        snackbarHostState.showSnackbar(
                            message = message,
                            duration = SnackbarDuration.Short,
                        )
                    }
                }

                fun showUndoNotice(message: String, onUndo: () -> Unit) {
                    uiScope.launch {
                        snackbarHostState.currentSnackbarData?.dismiss()
                        val res = snackbarHostState.showSnackbar(
                            message = message,
                            actionLabel = "Undo",
                            duration = SnackbarDuration.Short,
                        )
                        if (res == SnackbarResult.ActionPerformed) {
                            onUndo()
                        }
                    }
                }

                var activeTab by rememberSaveable { mutableStateOf(MainTab.TUNNEL) }
                val saveableStateHolder = rememberSaveableStateHolder()
                val backdropLayer = rememberGraphicsLayer()

                val showReconnectPopup = reconnectPopupVisible &&
                    (tunnelPhase == TunnelPhase.CONNECTED || tunnelPhase == TunnelPhase.CONNECTING)
                val showLiveMiniBar = activeTab != MainTab.TUNNEL && tunnelPhase != TunnelPhase.DISCONNECTED

                val density = LocalDensity.current
                val isImeVisible = WindowInsets.ime.getBottom(density) > 0
                val navBarBottomInset = with(density) {
                    WindowInsets.navigationBars.getBottom(this).toDp()
                }

                val topOverlayPadding by animateDpAsState(
                    targetValue = if (showReconnectPopup) 78.dp else 0.dp,
                    animationSpec = spring(dampingRatio = 0.78f, stiffness = 320f),
                    label = "topOverlayPadding",
                )
                val bottomChromePadding by animateDpAsState(
                    targetValue = navBarBottomInset + if (showLiveMiniBar) 154.dp else 98.dp,
                    animationSpec = spring(dampingRatio = 0.84f, stiffness = 310f),
                    label = "bottomChromePadding",
                )

                CompositionLocalProvider(
                    LocalGlassBackdropLayer provides backdropLayer,
                    LocalBottomChromePadding provides bottomChromePadding,
                    LocalTopOverlayPadding provides topOverlayPadding,
                ) {
                    Box(modifier = Modifier.fillMaxSize()) {
                        // Content layer captured into backdropLayer on API 31+ so floating chrome blurs live content.
                        // Override LocalGlassBackdropLayer to null inside the recorded subtree to prevent self-recursion.
                        Box(
                            modifier = Modifier
                                .fillMaxSize()
                                .drawWithContent {
                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                                        backdropLayer.record {
                                            this@drawWithContent.drawContent()
                                        }
                                        drawLayer(backdropLayer)
                                    } else {
                                        drawContent()
                                    }
                                },
                        ) {
                            CompositionLocalProvider(LocalGlassBackdropLayer provides null) {
                                AmbientCanvasBackdrop(
                                    phase = tunnelPhase,
                                    modifier = Modifier.fillMaxSize(),
                                )

                                Box(
                                    modifier = Modifier
                                        .fillMaxSize()
                                        .imePadding(),
                                ) {
                                    Crossfade(
                                        targetState = activeTab,
                                        animationSpec = tween(160),
                                        label = "mainTabCrossfade",
                                    ) { tab ->
                                        saveableStateHolder.SaveableStateProvider(tab) {
                                            when (tab) {
                                                MainTab.TUNNEL -> TunnelScreen(
                                                    tunnelState = viewModel.tunnelState,
                                                    settings = settings,
                                                    doctorState = doctorState,
                                                    engineVersion = viewModel.engineVersion,
                                                    pendingReconnect = pendingReconnect,
                                                    onToggleTunnel = ::toggleTunnel,
                                                    onReconnect = ::triggerReconnect,
                                                    onRunDoctor = viewModel::runDiagnostics,
                                                    onClearCache = { viewModel.clearNativeCache() },
                                                )

                                                MainTab.APPS -> AppsScreen(
                                                    settings = settings,
                                                    apps = apps,
                                                    loading = appsLoading,
                                                    onSetSplitMode = viewModel::setSplitTunnelMode,
                                                    onTogglePackage = viewModel::toggleSplitPackage,
                                                    onClearPackages = {
                                                        val previous = settings.splitPackages
                                                        if (previous.isNotEmpty()) {
                                                            viewModel.clearSplitPackages()
                                                            showUndoNotice("Cleared ${previous.size} selected apps") {
                                                                viewModel.restoreSplitPackages(previous)
                                                            }
                                                        }
                                                    },
                                                )

                                                MainTab.SETTINGS -> SettingsScreen(
                                                    settings = settings,
                                                    engineVersion = viewModel.engineVersion,
                                                    onSetDesyncMode = viewModel::setDesyncMode,
                                                    onSetChunkSize = viewModel::setChunkSize,
                                                    onSetDnsAddr = { addr ->
                                                        viewModel.setDnsAddr(addr)
                                                        showNotice("DNS updated to $addr")
                                                    },
                                                    onSetEnableDoh = viewModel::setEnableDoh,
                                                    onSetIpv4Only = viewModel::setIpv4Only,
                                                    onSetBlockQuic = viewModel::setBlockQuic,
                                                    onAddBypassDomain = { domain ->
                                                        viewModel.addBypassDomain(domain)
                                                        showNotice("Added $domain to bypass list")
                                                    },
                                                    onRemoveBypassDomain = { domain ->
                                                        viewModel.removeBypassDomain(domain)
                                                        showUndoNotice("Removed $domain") {
                                                            viewModel.addBypassDomain(domain)
                                                        }
                                                    },
                                                    onSetTheme = viewModel::setTheme,
                                                    onOpenAlwaysOnVpn = {
                                                        val opened = runCatching {
                                                            startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
                                                        }.isSuccess
                                                        if (!opened) {
                                                            showNotice("System VPN settings unavailable on this device")
                                                        }
                                                    },
                                                    onClearCache = {
                                                        viewModel.clearNativeCache {
                                                            showNotice("Adaptive cache cleared")
                                                        }
                                                    },
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Layer 1 (Top Overlay): Cross-tab Liquid Glass Reconnect Popup
                        Box(
                            modifier = Modifier
                                .align(Alignment.TopCenter)
                                .statusBarsPadding()
                                .displayCutoutPadding()
                                .padding(horizontal = 16.dp, vertical = 8.dp),
                        ) {
                            AnimatedVisibility(
                                visible = showReconnectPopup,
                                enter = slideInVertically(animationSpec = VdpiMotion.popupSpring) { -it } +
                                    fadeIn(tween(180)) +
                                    scaleIn(initialScale = 0.94f, animationSpec = tween(200)),
                                exit = slideOutVertically(animationSpec = tween(200)) { -it } +
                                    fadeOut(tween(160)) +
                                    scaleOut(targetScale = 0.96f, animationSpec = tween(180)),
                            ) {
                                TopReconnectGlassPopup(
                                    pendingChangeSummary = pendingChangeSummary,
                                    onReconnect = ::triggerReconnect,
                                    onDismiss = viewModel::dismissReconnectPopup,
                                )
                            }
                        }

                        // Layer 2 (Bottom Overlay): Snackbar + Floating Live Tunnel Bar + Sliding-Lens Glass Tab Bar
                        Column(
                            modifier = Modifier
                                .align(Alignment.BottomCenter)
                                .fillMaxWidth()
                                .windowInsetsPadding(WindowInsets.navigationBars.union(WindowInsets.ime))
                                .padding(horizontal = 16.dp, vertical = 10.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                        ) {
                            MinimalSnackbarHost(
                                hostState = snackbarHostState,
                                modifier = Modifier.padding(bottom = 8.dp),
                            )

                            AnimatedVisibility(
                                visible = showLiveMiniBar && !isImeVisible,
                                enter = slideInVertically(animationSpec = VdpiMotion.miniBarSpring) { it } +
                                    fadeIn(tween(180)) +
                                    expandVertically(expandFrom = Alignment.Bottom),
                                exit = slideOutVertically(animationSpec = tween(180)) { it } +
                                    fadeOut(tween(140)) +
                                    shrinkVertically(shrinkTowards = Alignment.Bottom),
                            ) {
                                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                    FloatingLiveTunnelBar(
                                        tunnelState = viewModel.tunnelState,
                                        onOpenTunnel = { activeTab = MainTab.TUNNEL },
                                        onToggleTunnel = ::toggleTunnel,
                                    )
                                    Spacer(Modifier.height(8.dp))
                                }
                            }

                            AnimatedVisibility(
                                visible = !isImeVisible,
                                enter = slideInVertically(animationSpec = VdpiMotion.miniBarSpring) { it } +
                                    fadeIn(tween(180)),
                                exit = slideOutVertically(animationSpec = tween(160)) { it } +
                                    fadeOut(tween(120)),
                            ) {
                                LiquidGlassTabBar(
                                    activeTab = activeTab,
                                    tunnelPhase = tunnelPhase,
                                    pendingReconnect = pendingReconnect,
                                    onSelect = { tab ->
                                        val switched = tab != activeTab
                                        activeTab = tab
                                        if (switched && tab == MainTab.APPS) {
                                            viewModel.loadInstalledApps()
                                        }
                                    },
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(KEY_NOTIF_PERMISSION_REQUESTED, notificationPermissionRequestedThisSession)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (intent.getBooleanExtra(EXTRA_AUTO_CONNECT, false)) {
            intent.removeExtra(EXTRA_AUTO_CONNECT)
            requestConnect()
        }
    }

    private fun toggleTunnel() {
        val phase = viewModel.tunnelPhase.value
        if (phase == TunnelPhase.CONNECTED || phase == TunnelPhase.CONNECTING) {
            viewModel.clearPendingReconnect()
            VdpiVpnService.stop(this)
        } else {
            requestConnect()
        }
    }

    private fun triggerReconnect() {
        viewModel.clearPendingReconnect()
        if (VpnService.prepare(this) != null) {
            requestConnect()
        } else {
            VdpiVpnService.reconnect(this)
        }
    }

    private fun requestConnect() {
        viewModel.clearPendingReconnect()
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            startVpnServiceWithPermissions()
        }
    }

    private fun startVpnServiceWithPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !notificationPermissionRequestedThisSession) {
            val granted = ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notificationPermissionRequestedThisSession = true
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
        }
        VdpiVpnService.start(this)
    }

    private fun openAppNotificationSettings() {
        runCatching {
            val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
                putExtra(Settings.EXTRA_APP_PACKAGE, packageName)
            }
            startActivity(intent)
        }
    }

    companion object {
        const val EXTRA_AUTO_CONNECT = "com.vulninc.vdpi.extra.AUTO_CONNECT"
        private const val KEY_NOTIF_PERMISSION_REQUESTED = "notif_permission_requested_session"
    }
}

@Composable
private fun TopReconnectGlassPopup(
    pendingChangeSummary: String,
    onReconnect: () -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val density = LocalDensity.current

    var dragOffsetY by remember { mutableFloatStateOf(0f) }
    val animatedDragY by animateFloatAsState(
        targetValue = dragOffsetY,
        animationSpec = spring(dampingRatio = 0.78f, stiffness = 500f),
        label = "reconnectPopupDrag",
    )
    val dismissThresholdPx = with(density) { -28.dp.toPx() }

    val baseWarningTint = palette.warningTint.copy(alpha = if (palette.isDark) 0.34f else 0.24f)
    val resolvedFill = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        baseWarningTint
    } else {
        baseWarningTint.compositeOver(palette.glassFillElevated)
    }

    val reconnectInteraction = remember { MutableInteractionSource() }
    val dismissInteraction = remember { MutableInteractionSource() }

    LiquidGlassCapsule(
        modifier = modifier
            .fillMaxWidth()
            .widthIn(max = 440.dp)
            .offset { IntOffset(0, animatedDragY.roundToInt()) }
            .pointerInput(onDismiss) {
                var totalDrag = 0f
                var dismissed = false
                detectVerticalDragGestures(
                    onDragStart = {
                        totalDrag = 0f
                        dismissed = false
                    },
                    onDragEnd = {
                        if (!dismissed && totalDrag <= dismissThresholdPx) {
                            dismissed = true
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            onDismiss()
                        }
                        dragOffsetY = 0f
                    },
                    onDragCancel = {
                        dragOffsetY = 0f
                    },
                    onVerticalDrag = { _, dragAmount ->
                        totalDrag += dragAmount
                        dragOffsetY = if (totalDrag < 0f) {
                            totalDrag.coerceAtLeast(dismissThresholdPx * 1.8f)
                        } else {
                            (totalDrag * 0.18f).coerceAtMost(12f)
                        }
                        if (!dismissed && totalDrag <= dismissThresholdPx * 1.35f) {
                            dismissed = true
                            dragOffsetY = 0f
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            onDismiss()
                        }
                    },
                )
            },
        rimTint = palette.warning,
        fillTint = resolvedFill,
        elevated = true,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 14.dp, end = 6.dp, top = 8.dp, bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            PulsingPhaseDot(
                color = palette.warning,
                pulsing = true,
                dotSize = 8.dp,
            )

            Spacer(Modifier.width(10.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Settings changed",
                    style = VdpiTextStyles.rowTitle,
                    fontWeight = FontWeight.SemiBold,
                    color = palette.inkPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = if (pendingChangeSummary.isNotBlank()) {
                        "Reconnect · $pendingChangeSummary"
                    } else {
                        "Reconnect to apply"
                    },
                    style = VdpiTextStyles.caption,
                    color = palette.inkSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Spacer(Modifier.width(10.dp))

            Box(
                modifier = Modifier
                    .heightIn(min = 38.dp)
                    .springPress(interactionSource = reconnectInteraction, pressedScale = 0.94f)
                    .shadow(
                        elevation = 6.dp,
                        shape = CircleShape,
                        clip = false,
                        ambientColor = palette.warningGlow,
                        spotColor = palette.warningGlow,
                    )
                    .clip(CircleShape)
                    .background(palette.warning)
                    .clickable(
                        interactionSource = reconnectInteraction,
                        indication = null,
                        role = Role.Button,
                    ) {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        onReconnect()
                    }
                    .padding(horizontal = 14.dp, vertical = 8.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = "Reconnect",
                    fontFamily = GeistSans,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 12.5.sp,
                    color = Color(0xFF0A0F1A),
                )
            }

            Spacer(Modifier.width(4.dp))

            Box(
                modifier = Modifier
                    .size(40.dp)
                    .springPress(interactionSource = dismissInteraction, pressedScale = 0.90f)
                    .clip(CircleShape)
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
                        .size(36.dp)
                        .clip(CircleShape)
                        .background(palette.inkPrimary.copy(alpha = if (palette.isDark) 0.10f else 0.08f))
                        .border(1.dp, palette.border, CircleShape),
                    contentAlignment = Alignment.Center,
                ) {
                    Canvas(modifier = Modifier.size(10.dp)) {
                        val stroke = 1.7.dp.toPx()
                        drawLine(
                            color = palette.inkSecondary,
                            start = Offset(0f, 0f),
                            end = Offset(size.width, size.height),
                            strokeWidth = stroke,
                            cap = StrokeCap.Round,
                        )
                        drawLine(
                            color = palette.inkSecondary,
                            start = Offset(size.width, 0f),
                            end = Offset(0f, size.height),
                            strokeWidth = stroke,
                            cap = StrokeCap.Round,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun FloatingLiveTunnelBar(
    tunnelState: StateFlow<TunnelRuntimeSnapshot>,
    onOpenTunnel: () -> Unit,
    onToggleTunnel: () -> Unit,
    modifier: Modifier = Modifier,
) {
    // Scoped locally so 1Hz telemetry ticks never recompose MainActivity, AppsScreen, or SettingsScreen.
    val runtime by tunnelState.collectAsStateWithLifecycle()
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val barInteraction = remember { MutableInteractionSource() }

    val phase = runtime.phase
    val snap = runtime.telemetry
    val isActive = phase == TunnelPhase.CONNECTED || phase == TunnelPhase.CONNECTING

    val dotColor by animateColorAsState(
        targetValue = when (phase) {
            TunnelPhase.CONNECTED -> palette.signal
            TunnelPhase.CONNECTING -> palette.warning
            TunnelPhase.ERROR -> palette.danger
            TunnelPhase.DISCONNECTED -> palette.inkMuted
        },
        animationSpec = tween(220),
        label = "miniBarDot",
    )

    val rimTint = when (phase) {
        TunnelPhase.CONNECTED -> palette.signal
        TunnelPhase.CONNECTING -> palette.warning
        TunnelPhase.ERROR -> palette.danger
        TunnelPhase.DISCONNECTED -> null
    }

    val title = when (phase) {
        TunnelPhase.CONNECTED -> "Protected"
        TunnelPhase.CONNECTING -> "Connecting"
        TunnelPhase.ERROR -> "Interrupted"
        TunnelPhase.DISCONNECTED -> "Standby"
    }

    val subtitle = when (phase) {
        TunnelPhase.CONNECTED ->
            "Stage ${snap.stageNumber} · ↓ ${formatBytes(snap.bytesRx)}  ↑ ${formatBytes(snap.bytesTx)}"
        TunnelPhase.CONNECTING -> "Establishing local anti-DPI tunnel"
        TunnelPhase.ERROR -> runtime.errorMessage?.takeIf { it.isNotBlank() } ?: "Tunnel interrupted"
        TunnelPhase.DISCONNECTED -> "Tap to open tunnel"
    }

    LiquidGlassCapsule(
        modifier = modifier
            .fillMaxWidth()
            .widthIn(max = 420.dp)
            .height(52.dp)
            .springPress(interactionSource = barInteraction, pressedScale = 0.98f),
        rimTint = rimTint,
        elevated = true,
    ) {
        Row(
            modifier = Modifier
                .fillMaxSize()
                .clickable(
                    interactionSource = barInteraction,
                    indication = null,
                    role = Role.Button,
                ) {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onOpenTunnel()
                }
                .padding(start = 14.dp, end = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            PulsingPhaseDot(
                color = dotColor,
                pulsing = isActive,
                dotSize = 8.dp,
            )

            Spacer(Modifier.width(10.dp))

            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.Center,
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        text = title,
                        style = VdpiTextStyles.rowTitle,
                        fontWeight = FontWeight.SemiBold,
                        color = palette.inkPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    if (phase == TunnelPhase.CONNECTED) {
                        Text(
                            text = formatUptime(snap.uptimeSecs),
                            style = VdpiTextStyles.monoSmall,
                            color = palette.inkMuted,
                            maxLines = 1,
                        )
                    }
                }
                Text(
                    text = subtitle,
                    style = VdpiTextStyles.monoSmall,
                    color = if (phase == TunnelPhase.ERROR) palette.danger else palette.inkSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Spacer(Modifier.width(8.dp))

            FloatingGlassIconButton(
                onClick = onToggleTunnel,
                contentDescription = if (isActive) "Disconnect tunnel" else "Connect tunnel",
                size = 36.dp,
            ) {
                PowerGlyph(
                    tint = if (isActive) palette.danger else palette.signal,
                    modifier = Modifier.size(16.dp),
                )
            }
        }
    }
}

@Composable
private fun LiquidGlassTabBar(
    activeTab: MainTab,
    tunnelPhase: TunnelPhase,
    pendingReconnect: Boolean,
    onSelect: (MainTab) -> Unit,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val tabs = MainTab.entries
    val selectedIndex = tabs.indexOf(activeTab).coerceAtLeast(0)

    val lensRim = remember(palette.glassRimTop, palette.glassRimSide, palette.glassRimBottom) {
        Brush.verticalGradient(
            0.00f to palette.glassRimTop,
            0.38f to palette.glassRimSide,
            0.80f to palette.glassRimSide,
            1.00f to palette.glassRimBottom,
        )
    }

    val lensGlowTint by animateColorAsState(
        targetValue = when {
            activeTab == MainTab.TUNNEL && tunnelPhase == TunnelPhase.CONNECTED && pendingReconnect ->
                palette.warning.copy(alpha = if (palette.isDark) 0.16f else 0.10f)
            activeTab == MainTab.TUNNEL && tunnelPhase == TunnelPhase.CONNECTED ->
                palette.signal.copy(alpha = if (palette.isDark) 0.16f else 0.10f)
            else -> Color.Transparent
        },
        animationSpec = tween(240),
        label = "tabLensGlow",
    )

    LiquidGlassCapsule(
        modifier = modifier
            .fillMaxWidth()
            .widthIn(max = 360.dp)
            .height(64.dp),
        elevated = true,
    ) {
        BoxWithConstraints(
            modifier = Modifier
                .fillMaxSize()
                .padding(5.dp),
        ) {
            val tabWidth = maxWidth / tabs.size
            val tabHeight = maxHeight
            val targetOffset = tabWidth * selectedIndex
            val lensOffset by animateDpAsState(
                targetValue = targetOffset,
                animationSpec = VdpiMotion.tabLensSpring,
                label = "tabLensOffset",
            )
            val travelFraction = if (tabWidth.value > 0f) {
                (abs(lensOffset.value - targetOffset.value) / tabWidth.value).coerceIn(0f, 1f)
            } else {
                0f
            }
            val lensStretchX = 1f + travelFraction * 0.10f
            val lensSquashY = 1f - travelFraction * 0.04f

            // Sliding glowing convex glass lens behind the selected tab
            Box(
                modifier = Modifier
                    .offset { IntOffset(lensOffset.roundToPx(), 0) }
                    .width(tabWidth)
                    .height(tabHeight)
                    .graphicsLayer {
                        scaleX = lensStretchX
                        scaleY = lensSquashY
                    }
                    .shadow(
                        elevation = if (palette.isDark) 8.dp else 5.dp,
                        shape = CircleShape,
                        clip = false,
                        ambientColor = palette.glassShadow,
                        spotColor = palette.glassShadow,
                    )
                    .clip(CircleShape)
                    .background(palette.glassLensFill)
                    .drawBehind {
                        if (lensGlowTint != Color.Transparent) {
                            drawRect(
                                brush = Brush.radialGradient(
                                    colors = listOf(lensGlowTint, Color.Transparent),
                                    center = Offset(size.width * 0.5f, size.height * 0.5f),
                                    radius = size.maxDimension * 0.65f,
                                ),
                            )
                        }
                        drawRect(
                            brush = Brush.verticalGradient(
                                0.00f to palette.glassSheenTop,
                                0.48f to Color.Transparent,
                                1.00f to Color.White.copy(alpha = if (palette.isDark) 0.04f else 0.18f),
                            ),
                        )
                    }
                    .border(width = 1.dp, brush = lensRim, shape = CircleShape),
            )

            Row(
                modifier = Modifier.fillMaxSize(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                tabs.forEach { tab ->
                    val selected = tab == activeTab
                    val interactionSource = remember { MutableInteractionSource() }
                    val iconScale by animateFloatAsState(
                        targetValue = if (selected) 1.08f else 1f,
                        animationSpec = VdpiMotion.tabLensFloatSpring,
                        label = "tabIconScale",
                    )
                    val tint by animateColorAsState(
                        targetValue = if (selected) palette.inkPrimary else palette.inkMuted,
                        animationSpec = tween(180),
                        label = "tabTint",
                    )

                    val statusDotColor = if (tab == MainTab.TUNNEL && tunnelPhase == TunnelPhase.CONNECTED) {
                        if (pendingReconnect) palette.warning else palette.signal
                    } else {
                        null
                    }
                    val statusDotGlow = if (pendingReconnect) palette.warningGlow else palette.signalGlow

                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxHeight()
                            .clip(CircleShape)
                            .springPress(interactionSource = interactionSource, pressedScale = 0.94f)
                            .selectable(
                                selected = selected,
                                interactionSource = interactionSource,
                                indication = null,
                                role = Role.Tab,
                                onClick = {
                                    if (!selected) {
                                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                        onSelect(tab)
                                    }
                                },
                            ),
                        contentAlignment = Alignment.Center,
                    ) {
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.Center,
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                MinimalTabIcon(
                                    kind = tab.icon,
                                    tint = tint,
                                    modifier = Modifier
                                        .size(22.dp)
                                        .graphicsLayer {
                                            scaleX = iconScale
                                            scaleY = iconScale
                                        },
                                )
                                if (statusDotColor != null) {
                                    Box(
                                        modifier = Modifier
                                            .align(Alignment.TopEnd)
                                            .offset(x = 5.dp, y = (-2).dp)
                                            .size(6.dp)
                                            .shadow(
                                                elevation = 4.dp,
                                                shape = CircleShape,
                                                clip = false,
                                                ambientColor = statusDotGlow,
                                                spotColor = statusDotGlow,
                                            )
                                            .clip(CircleShape)
                                            .background(statusDotColor),
                                    )
                                }
                            }
                            Spacer(Modifier.height(3.dp))
                            Text(
                                text = tab.label,
                                style = VdpiTextStyles.tabLabel,
                                fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium,
                                color = tint,
                                maxLines = 1,
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun PulsingPhaseDot(
    color: Color,
    pulsing: Boolean,
    dotSize: Dp = 8.dp,
) {
    Box(
        modifier = Modifier.size(dotSize + 6.dp),
        contentAlignment = Alignment.Center,
    ) {
        if (pulsing) {
            val infinite = rememberInfiniteTransition(label = "phaseDotPulse")
            val pulseScale by infinite.animateFloat(
                initialValue = 1f,
                targetValue = 2.3f,
                animationSpec = infiniteRepeatable(
                    animation = tween(1600, easing = FastOutSlowInEasing),
                    repeatMode = RepeatMode.Restart,
                ),
                label = "phaseDotScale",
            )
            val pulseAlpha by infinite.animateFloat(
                initialValue = 0.45f,
                targetValue = 0f,
                animationSpec = infiniteRepeatable(
                    animation = tween(1600, easing = FastOutSlowInEasing),
                    repeatMode = RepeatMode.Restart,
                ),
                label = "phaseDotAlpha",
            )
            Box(
                modifier = Modifier
                    .size(dotSize)
                    .graphicsLayer {
                        scaleX = pulseScale
                        scaleY = pulseScale
                        alpha = pulseAlpha
                    }
                    .clip(CircleShape)
                    .background(color),
            )
        }
        Box(
            modifier = Modifier
                .size(dotSize)
                .clip(CircleShape)
                .background(color),
        )
    }
}

@Composable
private fun PowerGlyph(
    tint: Color,
    modifier: Modifier = Modifier,
) {
    Canvas(modifier = modifier) {
        val strokeWidth = 1.8.dp.toPx()
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
