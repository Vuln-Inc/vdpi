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
import androidx.compose.animation.Crossfade
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.vulninc.vdpi.ui.VdpiViewModel
import com.vulninc.vdpi.ui.components.HairlineRule
import com.vulninc.vdpi.ui.components.MinimalSnackbarHost
import com.vulninc.vdpi.ui.components.MinimalTabIcon
import com.vulninc.vdpi.ui.components.TabIconKind
import com.vulninc.vdpi.ui.screens.AppsScreen
import com.vulninc.vdpi.ui.screens.SettingsScreen
import com.vulninc.vdpi.ui.screens.TunnelScreen
import com.vulninc.vdpi.ui.theme.GeistSans
import com.vulninc.vdpi.ui.theme.VdpiTheme
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens
import com.vulninc.vdpi.vpn.TunnelPhase
import com.vulninc.vdpi.vpn.VdpiVpnService
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.launch

private enum class MainTab(val label: String, val icon: TabIconKind) {
    TUNNEL("Tunnel", TabIconKind.TUNNEL),
    APPS("Apps", TabIconKind.APPS),
    SETTINGS("Settings", TabIconKind.SETTINGS),
}

class MainActivity : ComponentActivity() {

    private val viewModel: VdpiViewModel by viewModels()
    private val uiFeedback = MutableSharedFlow<String>(extraBufferCapacity = 4)

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnServiceWithPermissions()
        } else {
            uiFeedback.tryEmit("VPN permission was denied")
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {
        // Proceed regardless of notification permission; VPN still functions cleanly.
        VdpiVpnService.start(this)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        if (savedInstanceState == null && intent?.getBooleanExtra(EXTRA_AUTO_CONNECT, false) == true) {
            intent?.removeExtra(EXTRA_AUTO_CONNECT)
            requestConnect()
        }

        setContent {
            val settings by viewModel.settings.collectAsStateWithLifecycle()
            val apps by viewModel.installedApps.collectAsStateWithLifecycle()
            val appsLoading by viewModel.appsLoading.collectAsStateWithLifecycle()
            val doctorState by viewModel.doctorState.collectAsStateWithLifecycle()
            val pendingReconnect by viewModel.pendingReconnect.collectAsStateWithLifecycle()

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
                    uiFeedback.collect { msg ->
                        snackbarHostState.currentSnackbarData?.dismiss()
                        snackbarHostState.showSnackbar(
                            message = msg,
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

                Scaffold(
                    modifier = Modifier.fillMaxSize(),
                    containerColor = palette.canvas,
                    contentWindowInsets = WindowInsets(0, 0, 0, 0),
                    snackbarHost = { MinimalSnackbarHost(snackbarHostState) },
                    bottomBar = {
                        MinimalBottomBar(
                            activeTab = activeTab,
                            onSelect = { tab ->
                                activeTab = tab
                                if (tab == MainTab.APPS) {
                                    viewModel.loadInstalledApps()
                                }
                            },
                        )
                    },
                ) { innerPadding ->
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .statusBarsPadding()
                            .padding(innerPadding)
                            .imePadding(),
                    ) {
                        Crossfade(
                            targetState = activeTab,
                            animationSpec = tween(150),
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
                                        onToggleTunnel = {
                                            val phase = viewModel.tunnelState.value.phase
                                            if (phase == TunnelPhase.CONNECTED || phase == TunnelPhase.CONNECTING) {
                                                viewModel.clearPendingReconnect()
                                                VdpiVpnService.stop(this@MainActivity)
                                            } else {
                                                requestConnect()
                                            }
                                        },
                                        onReconnect = {
                                            viewModel.clearPendingReconnect()
                                            if (VpnService.prepare(this@MainActivity) != null) {
                                                requestConnect()
                                            } else {
                                                VdpiVpnService.reconnect(this@MainActivity)
                                            }
                                        },
                                        onRunDoctor = viewModel::runDiagnostics,
                                        onClearCache = {
                                            viewModel.clearNativeCache {
                                                showNotice("Adaptive cache cleared")
                                            }
                                        },
                                        onLogCopied = { showNotice("Engine log copied") },
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
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (intent.getBooleanExtra(EXTRA_AUTO_CONNECT, false)) {
            intent.removeExtra(EXTRA_AUTO_CONNECT)
            requestConnect()
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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
        }
        VdpiVpnService.start(this)
    }

    companion object {
        const val EXTRA_AUTO_CONNECT = "com.vulninc.vdpi.extra.AUTO_CONNECT"
    }
}

@Composable
private fun MinimalBottomBar(
    activeTab: MainTab,
    onSelect: (MainTab) -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val tabs = MainTab.entries
    val selectedIndex = tabs.indexOf(activeTab).coerceAtLeast(0)

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(palette.canvas)
            .navigationBarsPadding(),
    ) {
        HairlineRule()
        BoxWithConstraints(
            modifier = Modifier
                .fillMaxWidth()
                .height(60.dp),
        ) {
            val tabWidth = maxWidth / tabs.size
            val indicatorWidth = 28.dp
            val targetOffset = tabWidth * selectedIndex + (tabWidth - indicatorWidth) / 2
            val indicatorOffset by animateDpAsState(
                targetValue = targetOffset,
                animationSpec = spring(stiffness = Spring.StiffnessMediumLow, dampingRatio = 0.85f),
                label = "tabIndicator",
            )

            Box(
                modifier = Modifier
                    .offset { IntOffset(indicatorOffset.roundToPx(), 0) }
                    .width(indicatorWidth)
                    .height(2.dp)
                    .clip(RoundedCornerShape(bottomStart = 2.dp, bottomEnd = 2.dp))
                    .background(palette.inkPrimary),
            )

            Row(
                modifier = Modifier.fillMaxSize(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                tabs.forEach { tab ->
                    val selected = tab == activeTab
                    val tint = if (selected) palette.inkPrimary else palette.inkMuted
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .height(60.dp)
                            .selectable(
                                selected = selected,
                                role = Role.Tab,
                                onClick = { onSelect(tab) },
                            ),
                        contentAlignment = Alignment.Center,
                    ) {
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.Center,
                        ) {
                            MinimalTabIcon(kind = tab.icon, tint = tint)
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = tab.label,
                                fontFamily = GeistSans,
                                fontWeight = if (selected) FontWeight.Medium else FontWeight.Normal,
                                fontSize = 11.sp,
                                color = tint,
                            )
                        }
                    }
                }
            }
        }
    }
}
