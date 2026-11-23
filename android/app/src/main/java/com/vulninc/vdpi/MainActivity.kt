package com.vulninc.vdpi

import android.Manifest
import android.app.Activity
import android.app.UiModeManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color as AndroidColor
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
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
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
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
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.displayCutout
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
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.union
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
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
import androidx.compose.ui.graphics.layer.drawLayer
import androidx.compose.ui.graphics.rememberGraphicsLayer
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.util.VelocityTracker
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.vulninc.vdpi.ui.VdpiViewModel
import com.vulninc.vdpi.ui.components.LocalBottomChromePadding
import com.vulninc.vdpi.ui.components.LocalGlassBackdropLayer
import com.vulninc.vdpi.ui.components.LocalIncreaseContrast
import com.vulninc.vdpi.ui.components.LocalReduceTransparency
import com.vulninc.vdpi.ui.components.LocalTopOverlayPadding
import com.vulninc.vdpi.ui.components.MinimalSnackbarHost
import com.vulninc.vdpi.ui.components.MinimalTabIcon
import com.vulninc.vdpi.ui.components.ScrollEdgeFadeScrim
import com.vulninc.vdpi.ui.components.TabIconKind
import com.vulninc.vdpi.ui.components.VdpiMotion
import com.vulninc.vdpi.ui.components.liquidGlass
import com.vulninc.vdpi.ui.components.springPress
import com.vulninc.vdpi.ui.screens.AppsScreen
import com.vulninc.vdpi.ui.screens.SettingsScreen
import com.vulninc.vdpi.ui.screens.TunnelScreen
import com.vulninc.vdpi.ui.theme.GeistSans
import com.vulninc.vdpi.ui.theme.VdpiTextStyles
import com.vulninc.vdpi.ui.theme.VdpiTheme
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens
import com.vulninc.vdpi.util.formatBytes
import com.vulninc.vdpi.vpn.TunnelPhase
import com.vulninc.vdpi.vpn.TunnelRuntimeSnapshot
import com.vulninc.vdpi.vpn.VdpiVpnService
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import java.util.Locale
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

private data class ChromeAccessibilityState(
    val reduceMotion: Boolean = false,
    val reduceTransparency: Boolean = false,
    val increaseContrast: Boolean = false,
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
                val chromeA11y = rememberChromeAccessibilityState()
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
                val showLiveAccessoryPill = activeTab != MainTab.TUNNEL && tunnelPhase != TunnelPhase.DISCONNECTED

                val density = LocalDensity.current
                val imeBottomInset = with(density) { WindowInsets.ime.getBottom(this).toDp() }
                val isImeVisible = imeBottomInset > 0.dp
                val navBarBottomInset = with(density) { WindowInsets.navigationBars.getBottom(this).toDp() }
                val tabBarBottomOffset = maxOf(navBarBottomInset + 10.dp, 14.dp)

                val topOverlayPadding by animateDpAsState(
                    targetValue = if (showReconnectPopup) 74.dp else 0.dp,
                    animationSpec = if (chromeA11y.reduceMotion) {
                        tween(150)
                    } else {
                        spring(dampingRatio = 0.82f, stiffness = 340f)
                    },
                    label = "topOverlayPadding",
                )
                val bottomChromePadding by animateDpAsState(
                    targetValue = tabBarBottomOffset + if (showLiveAccessoryPill) 136.dp else 78.dp,
                    animationSpec = if (chromeA11y.reduceMotion) {
                        tween(150)
                    } else {
                        spring(dampingRatio = 0.84f, stiffness = 310f)
                    },
                    label = "bottomChromePadding",
                )
                val scrollEdgeScrimHeight by animateDpAsState(
                    targetValue = (tabBarBottomOffset + if (showLiveAccessoryPill) 148.dp else 90.dp)
                        .coerceAtLeast(96.dp),
                    animationSpec = if (chromeA11y.reduceMotion) {
                        tween(150)
                    } else {
                        spring(dampingRatio = 0.84f, stiffness = 310f)
                    },
                    label = "scrollEdgeScrimHeight",
                )
                val scrimAlpha by animateFloatAsState(
                    targetValue = if (isImeVisible) 0f else 1f,
                    animationSpec = tween(150),
                    label = "scrollEdgeScrimAlpha",
                )
                val snackbarDockClearance by animateDpAsState(
                    targetValue = tabBarBottomOffset + 62.dp + (if (showLiveAccessoryPill) 58.dp else 0.dp) + 8.dp,
                    animationSpec = if (chromeA11y.reduceMotion) {
                        tween(150)
                    } else {
                        spring(dampingRatio = 0.84f, stiffness = 310f)
                    },
                    label = "snackbarDockClearance",
                )
                val snackbarBottomOffset = if (isImeVisible) {
                    maxOf(imeBottomInset, navBarBottomInset) + 10.dp
                } else {
                    snackbarDockClearance
                }

                val sharedBackdropLayer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && !chromeA11y.reduceTransparency) {
                    backdropLayer
                } else {
                    null
                }

                CompositionLocalProvider(
                    LocalGlassBackdropLayer provides sharedBackdropLayer,
                    LocalBottomChromePadding provides bottomChromePadding,
                    LocalTopOverlayPadding provides topOverlayPadding,
                    LocalReduceTransparency provides chromeA11y.reduceTransparency,
                    LocalIncreaseContrast provides chromeA11y.increaseContrast,
                ) {
                    Box(modifier = Modifier.fillMaxSize()) {
                        // Z0: Full-bleed Content Layer on clean solid canvas (recorded into backdropLayer on API 31+).
                        // Override LocalGlassBackdropLayer to null inside recorded content so zero feedback loops occur.
                        Box(
                            modifier = Modifier
                                .fillMaxSize()
                                .drawWithContent {
                                    if (sharedBackdropLayer != null) {
                                        sharedBackdropLayer.record {
                                            this@drawWithContent.drawContent()
                                        }
                                        drawLayer(sharedBackdropLayer)
                                    } else {
                                        drawContent()
                                    }
                                },
                        ) {
                            CompositionLocalProvider(LocalGlassBackdropLayer provides null) {
                                Box(
                                    modifier = Modifier
                                        .fillMaxSize()
                                        .background(palette.canvas)
                                        .imePadding(),
                                ) {
                                    Crossfade(
                                        targetState = activeTab,
                                        animationSpec = tween(if (chromeA11y.reduceMotion) 150 else 160),
                                        label = "mainTabCrossfade",
                                    ) { tab ->
                                        saveableStateHolder.SaveableStateProvider(tab) {
                                            when (tab) {
                                                MainTab.TUNNEL -> TunnelScreen(
                                                    tunnelState = viewModel.tunnelState,
                                                    settings = settings,
                                                    doctorState = doctorState,
                                                    engineVersion = viewModel.engineVersion,
                                                    pendingReconnect = pendingReconnect && !showReconnectPopup,
                                                    onToggleTunnel = ::toggleTunnel,
                                                    onReconnect = ::triggerReconnect,
                                                    onRunDoctor = viewModel::runDiagnostics,
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

                        // Z10: Non-interactive Scroll Edge Dissolution scrim behind floating bottom dock.
                        if (scrimAlpha > 0.01f) {
                            ScrollEdgeFadeScrim(
                                modifier = Modifier
                                    .align(Alignment.BottomCenter)
                                    .graphicsLayer { alpha = scrimAlpha },
                                height = scrollEdgeScrimHeight,
                                fromBottom = true,
                            )
                        }

                        // Z20a: Floating Bottom HUD (Live Tunnel Accessory Pill + Capsule Tab Bar).
                        // Never applies imePadding() so chrome never rides above the software keyboard.
                        val hudSlidePx = with(density) { 24.dp.roundToPx() }
                        val pillSlidePx = with(density) { 12.dp.roundToPx() }
                        AnimatedVisibility(
                            visible = !isImeVisible,
                            modifier = Modifier
                                .align(Alignment.BottomCenter)
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp)
                                .padding(bottom = tabBarBottomOffset),
                            enter = if (chromeA11y.reduceMotion) {
                                fadeIn(tween(150))
                            } else {
                                slideInVertically(tween(200)) { hudSlidePx } + fadeIn(tween(180))
                            },
                            exit = if (chromeA11y.reduceMotion) {
                                fadeOut(tween(150))
                            } else {
                                slideOutVertically(tween(180)) { hudSlidePx } + fadeOut(tween(140))
                            },
                        ) {
                            Column(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalAlignment = Alignment.CenterHorizontally,
                            ) {
                                AnimatedVisibility(
                                    visible = showLiveAccessoryPill,
                                    enter = if (chromeA11y.reduceMotion) {
                                        fadeIn(tween(150))
                                    } else {
                                        slideInVertically(tween(220)) { pillSlidePx } +
                                            fadeIn(tween(220)) +
                                            expandVertically(tween(220), expandFrom = Alignment.Bottom)
                                    },
                                    exit = if (chromeA11y.reduceMotion) {
                                        fadeOut(tween(150))
                                    } else {
                                        slideOutVertically(tween(220)) { pillSlidePx } +
                                            fadeOut(tween(220)) +
                                            shrinkVertically(tween(220), shrinkTowards = Alignment.Bottom)
                                    },
                                ) {
                                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                        FloatingLiveTunnelAccessoryPill(
                                            tunnelState = viewModel.tunnelState,
                                            reduceMotion = chromeA11y.reduceMotion,
                                            reduceTransparency = chromeA11y.reduceTransparency,
                                            increaseContrast = chromeA11y.increaseContrast,
                                            onOpenTunnel = { activeTab = MainTab.TUNNEL },
                                            onDisconnect = ::disconnectTunnel,
                                        )
                                        Spacer(Modifier.height(8.dp))
                                    }
                                }

                                FloatingLiquidGlassTabBar(
                                    activeTab = activeTab,
                                    tunnelPhase = tunnelPhase,
                                    pendingReconnect = pendingReconnect,
                                    reduceMotion = chromeA11y.reduceMotion,
                                    reduceTransparency = chromeA11y.reduceTransparency,
                                    increaseContrast = chromeA11y.increaseContrast,
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

                        // Z20b: Floating Snackbar Host (stays visible above keyboard when IME is open).
                        MinimalSnackbarHost(
                            hostState = snackbarHostState,
                            modifier = Modifier
                                .align(Alignment.BottomCenter)
                                .padding(bottom = snackbarBottomOffset),
                        )

                        // Z30: Top-Floating "Settings Changed" Liquid Glass Popup across ALL tabs.
                        val popupSlidePx = with(density) { -24.dp.roundToPx() }
                        Box(
                            modifier = Modifier
                                .align(Alignment.TopCenter)
                                .windowInsetsPadding(WindowInsets.statusBars.union(WindowInsets.displayCutout))
                                .padding(horizontal = 16.dp)
                                .padding(top = 8.dp),
                        ) {
                            AnimatedVisibility(
                                visible = showReconnectPopup,
                                enter = if (chromeA11y.reduceMotion) {
                                    fadeIn(tween(150))
                                } else {
                                    slideInVertically(animationSpec = VdpiMotion.popupSpring) { popupSlidePx } +
                                        fadeIn(tween(180))
                                },
                                exit = if (chromeA11y.reduceMotion) {
                                    fadeOut(tween(150))
                                } else {
                                    slideOutVertically(animationSpec = tween(200)) { popupSlidePx } +
                                        fadeOut(tween(160))
                                },
                            ) {
                                TopReconnectGlassPopup(
                                    pendingChangeSummary = pendingChangeSummary,
                                    reduceMotion = chromeA11y.reduceMotion,
                                    reduceTransparency = chromeA11y.reduceTransparency,
                                    increaseContrast = chromeA11y.increaseContrast,
                                    onReconnect = ::triggerReconnect,
                                    onDismiss = viewModel::dismissReconnectPopup,
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
            disconnectTunnel()
        } else {
            requestConnect()
        }
    }

    private fun disconnectTunnel() {
        viewModel.clearPendingReconnect()
        VdpiVpnService.stop(this)
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
private fun rememberChromeAccessibilityState(): ChromeAccessibilityState {
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

@Composable
private fun TopReconnectGlassPopup(
    pendingChangeSummary: String,
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
            .fillMaxWidth()
            .widthIn(max = 420.dp)
            .heightIn(min = 56.dp)
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
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 14.dp, end = 2.dp, top = 6.dp, bottom = 6.dp),
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
                    val xColor = palette.inkPrimary.copy(alpha = 0.60f)
                    Canvas(modifier = Modifier.size(11.dp)) {
                        val stroke = 1.75.dp.toPx()
                        drawLine(
                            color = xColor,
                            start = Offset(0f, 0f),
                            end = Offset(size.width, size.height),
                            strokeWidth = stroke,
                            cap = StrokeCap.Round,
                        )
                        drawLine(
                            color = xColor,
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
private fun FloatingLiveTunnelAccessoryPill(
    tunnelState: StateFlow<TunnelRuntimeSnapshot>,
    reduceMotion: Boolean,
    reduceTransparency: Boolean,
    increaseContrast: Boolean,
    onOpenTunnel: () -> Unit,
    onDisconnect: () -> Unit,
    modifier: Modifier = Modifier,
) {
    // Scoped locally so 1Hz telemetry ticks never recompose MainActivity, AppsScreen, or SettingsScreen.
    val runtime by tunnelState.collectAsStateWithLifecycle()
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val pillInteraction = remember { MutableInteractionSource() }
    val stopInteraction = remember { MutableInteractionSource() }

    val phase = runtime.phase
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

    Box(
        modifier = modifier
            .fillMaxWidth()
            .widthIn(max = 340.dp)
            .heightIn(min = 50.dp)
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
                    .heightIn(min = 50.dp)
                    .clickable(
                        interactionSource = pillInteraction,
                        indication = null,
                        role = Role.Button,
                    ) {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onOpenTunnel()
                    }
                    .padding(start = 14.dp, end = 6.dp, top = 6.dp, bottom = 6.dp),
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
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
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
                        interactionSource = stopInteraction,
                        indication = null,
                        role = Role.Button,
                    ) {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        onDisconnect()
                    }
                    .semantics { contentDescription = "Disconnect tunnel" },
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
                                Modifier.springPress(interactionSource = stopInteraction, pressedScale = 0.92f)
                            },
                        )
                        .clip(CircleShape)
                        .background(buttonFill),
                    contentAlignment = Alignment.Center,
                ) {
                    PowerGlyph(
                        tint = palette.inkPrimary,
                        modifier = Modifier.size(15.dp),
                    )
                }
            }
        }
    }
}

@Composable
private fun FloatingLiquidGlassTabBar(
    activeTab: MainTab,
    tunnelPhase: TunnelPhase,
    pendingReconnect: Boolean,
    reduceMotion: Boolean,
    reduceTransparency: Boolean,
    increaseContrast: Boolean,
    onSelect: (MainTab) -> Unit,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val density = LocalDensity.current
    val tabs = MainTab.entries
    val selectedIndex = tabs.indexOf(activeTab).coerceAtLeast(0)

    val strongLensBorder = increaseContrast || reduceTransparency
    val lensFill = when {
        reduceTransparency -> palette.surfaceRaised
        palette.isDark -> Color.White.copy(alpha = 0.14f)
        else -> Color.White.copy(alpha = 0.74f)
    }
    val lensBorderWidth = if (strongLensBorder) 1.dp else 0.5.dp
    val lensRimColor = when {
        strongLensBorder -> palette.borderStrong
        palette.isDark -> Color.White.copy(alpha = 0.26f)
        else -> Color.Black.copy(alpha = 0.06f)
    }
    val lensShadowColor = Color.Black.copy(alpha = 0.08f)

    val currentActiveTab by rememberUpdatedState(activeTab)
    val currentOnSelect by rememberUpdatedState(onSelect)

    Box(
        modifier = modifier
            .fillMaxWidth()
            .widthIn(max = 340.dp)
            .height(62.dp)
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
                .padding(5.dp),
        ) {
            val tabWidth = maxWidth / tabs.size
            val tabHeight = maxHeight
            val tabWidthPx = with(density) { tabWidth.toPx() }
            val maxLensOffsetPx = (tabWidthPx * (tabs.size - 1)).coerceAtLeast(0f)

            var dragLensOffsetPx by remember { mutableFloatStateOf(Float.NaN) }
            val targetOffset = tabWidth * selectedIndex
            val animatedLensOffset by animateDpAsState(
                targetValue = targetOffset,
                animationSpec = if (reduceMotion) tween(150) else VdpiMotion.tabLensSpring,
                label = "tabLensOffset",
            )
            val effectiveLensOffset = if (!dragLensOffsetPx.isNaN()) {
                with(density) { dragLensOffsetPx.toDp() }
            } else {
                animatedLensOffset
            }

            val travelFraction = if (!reduceMotion && dragLensOffsetPx.isNaN() && tabWidth.value > 0f) {
                (abs(animatedLensOffset.value - targetOffset.value) / tabWidth.value).coerceIn(0f, 1f)
            } else {
                0f
            }
            val lensStretchX = 1f + travelFraction * 0.08f
            val lensSquashY = 1f - travelFraction * 0.03f

            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .pointerInput(tabs.size, tabWidthPx) {
                        if (tabWidthPx <= 0f) return@pointerInput
                        detectHorizontalDragGestures(
                            onDragStart = { startOffset ->
                                val clamped = (startOffset.x - tabWidthPx * 0.5f).coerceIn(0f, maxLensOffsetPx)
                                dragLensOffsetPx = clamped
                            },
                            onDragEnd = {
                                dragLensOffsetPx = Float.NaN
                            },
                            onDragCancel = {
                                dragLensOffsetPx = Float.NaN
                            },
                            onHorizontalDrag = { change, _ ->
                                val x = change.position.x
                                dragLensOffsetPx = (x - tabWidthPx * 0.5f).coerceIn(0f, maxLensOffsetPx)
                                val hoveredIdx = (x / tabWidthPx).toInt().coerceIn(0, tabs.lastIndex)
                                val hoveredTab = tabs[hoveredIdx]
                                if (hoveredTab != currentActiveTab) {
                                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    currentOnSelect(hoveredTab)
                                }
                            },
                        )
                    },
            ) {
                // Sliding convex specular glass lens (52dp tall, 26dp concentric radius)
                Box(
                    modifier = Modifier
                        .offset { IntOffset(effectiveLensOffset.roundToPx(), 0) }
                        .width(tabWidth)
                        .height(tabHeight)
                        .graphicsLayer {
                            scaleX = lensStretchX
                            scaleY = lensSquashY
                        }
                        .then(
                            if (reduceTransparency) {
                                Modifier
                            } else {
                                Modifier.shadow(
                                    elevation = 3.dp,
                                    shape = CircleShape,
                                    clip = false,
                                    ambientColor = lensShadowColor,
                                    spotColor = lensShadowColor,
                                )
                            },
                        )
                        .clip(CircleShape)
                        .background(lensFill)
                        .drawBehind {
                            if (!reduceTransparency) {
                                drawRect(
                                    brush = Brush.verticalGradient(
                                        0.00f to Color.White.copy(alpha = if (palette.isDark) 0.14f else 0.42f),
                                        0.48f to Color.Transparent,
                                        1.00f to Color.White.copy(alpha = if (palette.isDark) 0.03f else 0.14f),
                                    ),
                                )
                            }
                        }
                        .border(width = lensBorderWidth, color = lensRimColor, shape = CircleShape),
                )

                Row(
                    modifier = Modifier.fillMaxSize(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    tabs.forEach { tab ->
                        val selected = tab == activeTab
                        val interactionSource = remember { MutableInteractionSource() }
                        val tint by animateColorAsState(
                            targetValue = if (selected) {
                                palette.accent
                            } else {
                                palette.inkPrimary.copy(alpha = 0.60f)
                            },
                            animationSpec = tween(if (reduceMotion) 150 else 180),
                            label = "tabTint",
                        )

                        val statusDotColor = if (tab == MainTab.TUNNEL && tunnelPhase == TunnelPhase.CONNECTED) {
                            if (pendingReconnect) palette.warning else palette.signal
                        } else {
                            null
                        }

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
                                        filled = selected,
                                    )
                                    if (statusDotColor != null) {
                                        Box(
                                            modifier = Modifier
                                                .align(Alignment.TopEnd)
                                                .offset(x = 5.dp, y = (-2).dp)
                                                .size(6.dp)
                                                .clip(CircleShape)
                                                .background(statusDotColor),
                                        )
                                    }
                                }
                                Spacer(Modifier.height(2.dp))
                                Text(
                                    text = tab.label,
                                    style = VdpiTextStyles.tabLabel,
                                    color = tint,
                                    maxLines = 1,
                                    softWrap = false,
                                    overflow = TextOverflow.Clip,
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

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
private fun DownArrowGlyph(
    tint: Color,
    modifier: Modifier = Modifier,
) {
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
        val head = Path().apply {
            moveTo(w * 0.22f, h * 0.56f)
            lineTo(w * 0.50f, h * 0.84f)
            lineTo(w * 0.78f, h * 0.56f)
        }
        drawPath(path = head, color = tint, style = stroke)
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
