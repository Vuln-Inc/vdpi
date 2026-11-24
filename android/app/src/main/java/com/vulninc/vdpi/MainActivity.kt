package com.vulninc.vdpi

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.Configuration
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
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.union
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.layer.drawLayer
import androidx.compose.ui.graphics.rememberGraphicsLayer
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.vulninc.vdpi.ui.VdpiViewModel
import com.vulninc.vdpi.ui.chrome.FloatingLiquidGlassTabBar
import com.vulninc.vdpi.ui.chrome.FloatingLiveTunnelAccessoryPill
import com.vulninc.vdpi.ui.chrome.MainTab
import com.vulninc.vdpi.ui.chrome.TopReconnectGlassPopup
import com.vulninc.vdpi.ui.chrome.rememberChromeAccessibilityState
import com.vulninc.vdpi.ui.components.LocalBottomChromePadding
import com.vulninc.vdpi.ui.components.LocalGlassBackdropLayer
import com.vulninc.vdpi.ui.components.LocalIncreaseContrast
import com.vulninc.vdpi.ui.components.LocalReduceMotion
import com.vulninc.vdpi.ui.components.LocalReduceTransparency
import com.vulninc.vdpi.ui.components.LocalTopOverlayPadding
import com.vulninc.vdpi.ui.components.MinimalSnackbarHost
import com.vulninc.vdpi.ui.components.ScrollEdgeFadeScrim
import com.vulninc.vdpi.ui.components.VdpiMotion
import com.vulninc.vdpi.ui.screens.AppsScreen
import com.vulninc.vdpi.ui.screens.SettingsScreen
import com.vulninc.vdpi.ui.screens.TunnelScreen
import com.vulninc.vdpi.ui.theme.VdpiTheme
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens
import com.vulninc.vdpi.vpn.TunnelPhase
import com.vulninc.vdpi.vpn.VdpiVpnService
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.launch

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
            VdpiAppRoot(
                viewModel = viewModel,
                uiFeedback = uiFeedback,
                onSystemBarStyleChange = ::applySystemBarStyle,
                onToggleTunnel = ::toggleTunnel,
                onDisconnectTunnel = ::disconnectTunnel,
                onTriggerReconnect = ::triggerReconnect,
                onRequestConnect = ::requestConnect,
                onOpenAlwaysOnVpn = ::openAlwaysOnVpnSettings,
            )
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

    private fun applySystemBarStyle(isDark: Boolean) {
        val barStyle = if (isDark) {
            SystemBarStyle.dark(AndroidColor.TRANSPARENT)
        } else {
            SystemBarStyle.light(AndroidColor.TRANSPARENT, AndroidColor.TRANSPARENT)
        }
        enableEdgeToEdge(statusBarStyle = barStyle, navigationBarStyle = barStyle)
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
        viewModel.resetForExplicitReconnect()
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

    private fun openAlwaysOnVpnSettings(): Boolean =
        runCatching { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }.isSuccess

    companion object {
        const val EXTRA_AUTO_CONNECT = "com.vulninc.vdpi.extra.AUTO_CONNECT"
        private const val KEY_NOTIF_PERMISSION_REQUESTED = "notif_permission_requested_session"
    }
}

@Composable
private fun VdpiAppRoot(
    viewModel: VdpiViewModel,
    uiFeedback: SharedFlow<UiFeedbackEvent>,
    onSystemBarStyleChange: (isDark: Boolean) -> Unit,
    onToggleTunnel: () -> Unit,
    onDisconnectTunnel: () -> Unit,
    onTriggerReconnect: () -> Unit,
    onRequestConnect: () -> Unit,
    onOpenAlwaysOnVpn: () -> Boolean,
) {
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
            onSystemBarStyleChange(palette.isDark)
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

        val showReconnectPopup = reconnectPopupVisible &&
            (tunnelPhase == TunnelPhase.CONNECTED || tunnelPhase == TunnelPhase.CONNECTING)
        val showLiveAccessoryPill = activeTab != MainTab.TUNNEL && tunnelPhase != TunnelPhase.DISCONNECTED

        val configuration = LocalConfiguration.current
        val isLandscape = configuration.orientation == Configuration.ORIENTATION_LANDSCAPE &&
            configuration.screenWidthDp >= 560

        val density = LocalDensity.current
        val imeBottomInset = with(density) { WindowInsets.ime.getBottom(this).toDp() }
        val isImeVisible = imeBottomInset > 0.dp
        val navBarBottomInset = with(density) { WindowInsets.navigationBars.getBottom(this).toDp() }
        val tabBarBottomOffset = if (isLandscape) {
            maxOf(navBarBottomInset + 6.dp, 8.dp)
        } else {
            maxOf(navBarBottomInset + 10.dp, 14.dp)
        }

        val topOverlayPadding by animateDpAsState(
            targetValue = when {
                !showReconnectPopup -> 0.dp
                isLandscape -> 64.dp
                else -> 84.dp
            },
            animationSpec = if (chromeA11y.reduceMotion) {
                tween(150)
            } else {
                spring(dampingRatio = 0.82f, stiffness = 340f)
            },
            label = "topOverlayPadding",
        )
        val bottomChromePadding by animateDpAsState(
            targetValue = tabBarBottomOffset + if (isLandscape) {
                if (showLiveAccessoryPill) 114.dp else 64.dp
            } else {
                if (showLiveAccessoryPill) 136.dp else 78.dp
            },
            animationSpec = if (chromeA11y.reduceMotion) {
                tween(150)
            } else {
                spring(dampingRatio = 0.84f, stiffness = 310f)
            },
            label = "bottomChromePadding",
        )
        val scrollEdgeScrimHeight = bottomChromePadding + 28.dp
        val scrimAlpha by animateFloatAsState(
            targetValue = if (isImeVisible) 0f else 1f,
            animationSpec = tween(150),
            label = "scrollEdgeScrimAlpha",
        )
        val snackbarDockClearance by animateDpAsState(
            targetValue = tabBarBottomOffset +
                (if (isLandscape) 50.dp else 62.dp) +
                (if (showLiveAccessoryPill) (if (isLandscape) 50.dp else 58.dp) else 0.dp) +
                8.dp,
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

        val useBackdropBlur = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && !chromeA11y.reduceTransparency
        val sharedBackdropLayer = if (useBackdropBlur) {
            rememberGraphicsLayer()
        } else {
            null
        }

        CompositionLocalProvider(
            LocalGlassBackdropLayer provides sharedBackdropLayer,
            LocalBottomChromePadding provides bottomChromePadding,
            LocalTopOverlayPadding provides topOverlayPadding,
            LocalReduceMotion provides chromeA11y.reduceMotion,
            LocalReduceTransparency provides chromeA11y.reduceTransparency,
            LocalIncreaseContrast provides chromeA11y.increaseContrast,
        ) {
            Box(modifier = Modifier.fillMaxSize()) {
                // Z0: Full-bleed Content Layer on clean solid canvas (recorded into backdropLayer on API 31+).
                // Override LocalGlassBackdropLayer to null inside recorded content so zero feedback loops occur.
                val contentBackdropModifier = if (sharedBackdropLayer != null) {
                    Modifier.drawWithContent {
                        sharedBackdropLayer.record {
                            this@drawWithContent.drawContent()
                        }
                        drawLayer(sharedBackdropLayer)
                    }
                } else {
                    Modifier
                }
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .then(contentBackdropModifier),
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
                                            onToggleTunnel = onToggleTunnel,
                                            onReconnect = onTriggerReconnect,
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
                                                if (!onOpenAlwaysOnVpn()) {
                                                    showNotice("System VPN settings unavailable on this device")
                                                }
                                            },
                                            onClearCache = {
                                                viewModel.clearNativeCache { cleared ->
                                                    showNotice(
                                                        if (cleared) {
                                                            "Adaptive cache cleared"
                                                        } else {
                                                            "Cache resets when disconnected"
                                                        },
                                                    )
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
                        .padding(horizontal = 28.dp)
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
                                    fadeIn(tween(220))
                            },
                            exit = if (chromeA11y.reduceMotion) {
                                fadeOut(tween(150))
                            } else {
                                slideOutVertically(tween(220)) { pillSlidePx } +
                                    fadeOut(tween(220))
                            },
                        ) {
                            Column(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalAlignment = Alignment.CenterHorizontally,
                            ) {
                                FloatingLiveTunnelAccessoryPill(
                                    tunnelState = viewModel.tunnelState,
                                    isLandscape = isLandscape,
                                    reduceMotion = chromeA11y.reduceMotion,
                                    reduceTransparency = chromeA11y.reduceTransparency,
                                    increaseContrast = chromeA11y.increaseContrast,
                                    onOpenTunnel = { activeTab = MainTab.TUNNEL },
                                    onDisconnect = onDisconnectTunnel,
                                    onReconnect = onRequestConnect,
                                )
                                Spacer(Modifier.height(if (isLandscape) 6.dp else 8.dp))
                            }
                        }

                        FloatingLiquidGlassTabBar(
                            activeTab = activeTab,
                            tunnelPhase = tunnelPhase,
                            pendingReconnect = pendingReconnect,
                            isLandscape = isLandscape,
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
                        .windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal))
                        .widthIn(max = 520.dp)
                        .padding(bottom = snackbarBottomOffset),
                )

                // Z30: Top-Floating "Settings Changed" Liquid Glass Popup across ALL tabs.
                val popupSlidePx = with(density) { -24.dp.roundToPx() }
                Box(
                    modifier = Modifier
                        .align(Alignment.TopCenter)
                        .fillMaxWidth()
                        .windowInsetsPadding(
                            WindowInsets.statusBars
                                .union(WindowInsets.displayCutout)
                                .only(WindowInsetsSides.Top),
                        )
                        .padding(horizontal = 16.dp)
                        .padding(top = if (isLandscape) 4.dp else 8.dp),
                    contentAlignment = Alignment.TopCenter,
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
                            isLandscape = isLandscape,
                            reduceMotion = chromeA11y.reduceMotion,
                            reduceTransparency = chromeA11y.reduceTransparency,
                            increaseContrast = chromeA11y.increaseContrast,
                            onReconnect = onTriggerReconnect,
                            onDismiss = viewModel::dismissReconnectPopup,
                        )
                    }
                }
            }
        }
    }
}
