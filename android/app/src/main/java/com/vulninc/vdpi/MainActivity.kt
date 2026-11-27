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
import androidx.lifecycle.lifecycleScope
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
import com.vulninc.vdpi.ui.screens.UpdateBannerInfo
import com.vulninc.vdpi.ui.theme.VdpiTheme
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens
import com.vulninc.vdpi.vpn.TunnelPhase
import com.vulninc.vdpi.vpn.VdpiVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream

private class SettingsFileTooLargeException : Exception()

private data class UiFeedbackEvent(
    val message: String,
    val actionLabel: String? = null,
    val duration: SnackbarDuration = SnackbarDuration.Short,
    val onAction: (() -> Unit)? = null,
)

class MainActivity : ComponentActivity() {

    private val viewModel: VdpiViewModel by viewModels()
    private val uiFeedback = Channel<UiFeedbackEvent>(Channel.BUFFERED)
    private val uiFeedbackEvents: Flow<UiFeedbackEvent> = uiFeedback.receiveAsFlow()
    private var notificationPermissionRequestedThisSession = false

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnServiceWithPermissions()
        } else {
            uiFeedback.trySend(UiFeedbackEvent(message = "VPN permission was denied"))
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (!granted) {
            uiFeedback.trySend(
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
            uiFeedback.trySend(UiFeedbackEvent(message = "VPN permission required"))
        }
    }

    private val exportSettingsLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri ->
        if (uri == null) return@registerForActivityResult
        lifecycleScope.launch(Dispatchers.IO) {
            val payload = runCatching { viewModel.exportSettingsJsonSnapshot() }.getOrElse {
                uiFeedback.trySend(UiFeedbackEvent(message = "Failed to serialize settings"))
                return@launch
            }
            val written = runCatching {
                val stream = runCatching {
                    contentResolver.openOutputStream(uri, "wt")
                }.getOrElse {
                    contentResolver.openOutputStream(uri)
                }
                stream?.use { out ->
                    out.write(payload.toByteArray(Charsets.UTF_8))
                    out.flush()
                    true
                } ?: false
            }.getOrDefault(false)
            uiFeedback.trySend(
                UiFeedbackEvent(
                    message = if (written) "Settings exported" else "Failed to export settings",
                ),
            )
        }
    }

    private val importSettingsLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri == null) return@registerForActivityResult
        lifecycleScope.launch(Dispatchers.IO) {
            val readResult = runCatching {
                contentResolver.openInputStream(uri)?.use { stream ->
                    val buffer = ByteArray(8192)
                    val out = ByteArrayOutputStream()
                    var total = 0
                    while (true) {
                        val read = stream.read(buffer)
                        if (read < 0) break
                        if (read > 0) {
                            total += read
                            if (total > MAX_IMPORT_BYTES) {
                                throw SettingsFileTooLargeException()
                            }
                            out.write(buffer, 0, read)
                        }
                    }
                    out.toString(Charsets.UTF_8.name()).removePrefix("\uFEFF")
                } ?: error("Could not open settings file")
            }

            if (readResult.isFailure) {
                val message = when (readResult.exceptionOrNull()) {
                    is SettingsFileTooLargeException -> "Settings file too large (max 256 KB)"
                    else -> "Could not read settings file"
                }
                uiFeedback.trySend(UiFeedbackEvent(message = message))
                return@launch
            }

            val rawJson = readResult.getOrThrow()
            if (rawJson.isBlank()) {
                uiFeedback.trySend(UiFeedbackEvent(message = "Settings file is empty"))
                return@launch
            }

            withContext(Dispatchers.Main.immediate) {
                viewModel.importSettingsJson(rawJson)
            }
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
                uiFeedback = uiFeedbackEvents,
                onSystemBarStyleChange = ::applySystemBarStyle,
                onToggleTunnel = ::toggleTunnel,
                onDisconnectTunnel = ::disconnectTunnel,
                onTriggerReconnect = ::triggerReconnect,
                onRequestConnect = ::requestConnect,
                onOpenAlwaysOnVpn = ::openAlwaysOnVpnSettings,
                onExportSettings = ::launchExportSettings,
                onImportSettings = ::launchImportSettings,
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

    private fun launchExportSettings() {
        runCatching {
            exportSettingsLauncher.launch(SETTINGS_EXPORT_FILENAME)
        }.onFailure {
            uiFeedback.trySend(UiFeedbackEvent(message = "File picker unavailable"))
        }
    }

    private fun launchImportSettings() {
        runCatching {
            importSettingsLauncher.launch(
                arrayOf("application/json", "text/plain", "application/octet-stream"),
            )
        }.onFailure {
            uiFeedback.trySend(UiFeedbackEvent(message = "File picker unavailable"))
        }
    }

    companion object {
        const val EXTRA_AUTO_CONNECT = "com.vulninc.vdpi.extra.AUTO_CONNECT"
        private const val KEY_NOTIF_PERMISSION_REQUESTED = "notif_permission_requested_session"
        private const val SETTINGS_EXPORT_FILENAME = "vdpi-settings.json"
        private const val MAX_IMPORT_BYTES = 256 * 1024
    }
}

@Composable
private fun VdpiAppRoot(
    viewModel: VdpiViewModel,
    uiFeedback: Flow<UiFeedbackEvent>,
    onSystemBarStyleChange: (isDark: Boolean) -> Unit,
    onToggleTunnel: () -> Unit,
    onDisconnectTunnel: () -> Unit,
    onTriggerReconnect: () -> Unit,
    onRequestConnect: () -> Unit,
    onOpenAlwaysOnVpn: () -> Boolean,
    onExportSettings: () -> Unit,
    onImportSettings: () -> Unit,
) {
    val settings by viewModel.settings.collectAsStateWithLifecycle()
    val availableUpdate by viewModel.availableUpdate.collectAsStateWithLifecycle()
    val isCheckingUpdate by viewModel.isCheckingUpdate.collectAsStateWithLifecycle()
    val updateStatusMessage by viewModel.updateStatusMessage.collectAsStateWithLifecycle()
    val apps by viewModel.installedApps.collectAsStateWithLifecycle()
    val appsLoading by viewModel.appsLoading.collectAsStateWithLifecycle()
    val doctorState by viewModel.doctorState.collectAsStateWithLifecycle()
    val tunnelPhase by viewModel.tunnelPhase.collectAsStateWithLifecycle()
    val pendingReconnect by viewModel.pendingReconnect.collectAsStateWithLifecycle()
    val reconnectPopupVisible by viewModel.reconnectPopupVisible.collectAsStateWithLifecycle()
    val pendingChangeSummary by viewModel.pendingChangeSummary.collectAsStateWithLifecycle()

    val availableUpdateInfo = availableUpdate?.let { update ->
        UpdateBannerInfo(
            latestVersion = update.latestVersion,
            releaseUrl = update.releaseUrl,
        )
    }
    val appVersion = viewModel.appVersion.ifBlank { viewModel.engineVersion }

    VdpiTheme(preference = settings.theme) {
        val palette = VdpiThemeTokens.palette
        val chromeA11y = rememberChromeAccessibilityState()
        val snackbarHostState = remember { SnackbarHostState() }
        val uiScope = rememberCoroutineScope()

        LaunchedEffect(palette.isDark) {
            onSystemBarStyleChange(palette.isDark)
        }

        LaunchedEffect(uiFeedback) {
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

        LaunchedEffect(viewModel) {
            viewModel.userMessages.collect { message ->
                snackbarHostState.currentSnackbarData?.dismiss()
                snackbarHostState.showSnackbar(
                    message = message,
                    duration = SnackbarDuration.Short,
                )
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
                // Z0: Full-bleed content layer on canvas (recorded into backdropLayer on API 31+).
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
                                            throughputSamples = viewModel.throughputSamples,
                                            currentRateBytesPerSec = viewModel.currentRateBytesPerSec,
                                            settings = settings,
                                            doctorState = doctorState,
                                            pendingReconnect = pendingReconnect && !showReconnectPopup,
                                            onToggleTunnel = onToggleTunnel,
                                            onReconnect = onTriggerReconnect,
                                            onRunDoctor = viewModel::runDiagnostics,
                                            availableUpdate = availableUpdateInfo,
                                            onFormatDiagnosticsReport = viewModel::formatDiagnosticsReport,
                                            onDismissUpdate = viewModel::dismissAvailableUpdate,
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
                                            engineVersion = appVersion,
                                            onSetDesyncMode = viewModel::setDesyncMode,
                                            onSetChunkSize = viewModel::setChunkSize,
                                            onSetDnsAddr = { addr ->
                                                viewModel.setDnsAddr(addr)
                                                showNotice("DNS updated to ${formatDnsDisplayAddr(addr)}")
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
                                                            "Failed to clear adaptive cache"
                                                        },
                                                    )
                                                }
                                            },
                                            availableUpdate = availableUpdateInfo,
                                            isCheckingUpdate = isCheckingUpdate,
                                            updateStatusMessage = updateStatusMessage,
                                            onCheckForUpdates = { viewModel.checkForUpdates(manual = true) },
                                            onExportSettings = onExportSettings,
                                            onImportSettings = onImportSettings,
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                // Z10: Non-interactive bottom fade scrim behind floating navigation bar.
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
                            showSettingsBadge = availableUpdate != null,
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

                // Z30: Top-floating "Settings Changed" reconnect popup across all tabs.
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

private fun formatDnsDisplayAddr(rawAddr: String): String {
    val addr = rawAddr.trim().ifBlank { "1.1.1.1" }
    return if (addr.startsWith("https://", ignoreCase = true)) {
        runCatching { java.net.URI(addr).host }.getOrNull()?.takeIf { it.isNotBlank() } ?: "custom DoH"
    } else {
        addr
    }
}
