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
import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.vulninc.vdpi.ui.VdpiViewModel
import com.vulninc.vdpi.ui.components.HairlineRule
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

private enum class MainTab(val label: String, val icon: TabIconKind) {
    TUNNEL("Tunnel", TabIconKind.TUNNEL),
    APPS("Apps", TabIconKind.APPS),
    SETTINGS("Settings", TabIconKind.SETTINGS),
}

class MainActivity : ComponentActivity() {

    private val viewModel: VdpiViewModel by viewModels()

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnServiceWithPermissions()
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

        if (intent?.getBooleanExtra(EXTRA_AUTO_CONNECT, false) == true) {
            requestConnect()
        }

        setContent {
            val settings by viewModel.settings.collectAsState()
            val runtime by viewModel.tunnelState.collectAsState()
            val apps by viewModel.installedApps.collectAsState()
            val appsLoading by viewModel.appsLoading.collectAsState()
            val doctorState by viewModel.doctorState.collectAsState()
            val pendingReconnect by viewModel.pendingReconnect.collectAsState()

            VdpiTheme(preference = settings.theme) {
                val palette = VdpiThemeTokens.palette
                SideEffect {
                    val barStyle = if (palette.isDark) {
                        SystemBarStyle.dark(AndroidColor.TRANSPARENT)
                    } else {
                        SystemBarStyle.light(AndroidColor.TRANSPARENT, AndroidColor.TRANSPARENT)
                    }
                    enableEdgeToEdge(statusBarStyle = barStyle, navigationBarStyle = barStyle)
                }

                var activeTab by rememberSaveable { mutableStateOf(MainTab.TUNNEL) }

                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(palette.canvas)
                        .statusBarsPadding(),
                ) {
                    Box(modifier = Modifier.weight(1f)) {
                        when (activeTab) {
                            MainTab.TUNNEL -> TunnelScreen(
                                runtime = runtime,
                                settings = settings,
                                doctorState = doctorState,
                                engineVersion = viewModel.engineVersion,
                                pendingReconnect = pendingReconnect,
                                onToggleTunnel = {
                                    if (runtime.phase == TunnelPhase.CONNECTED ||
                                        runtime.phase == TunnelPhase.CONNECTING
                                    ) {
                                        viewModel.clearPendingReconnect()
                                        VdpiVpnService.stop(this@MainActivity)
                                    } else {
                                        requestConnect()
                                    }
                                },
                                onReconnect = {
                                    viewModel.clearPendingReconnect()
                                    VdpiVpnService.stop(this@MainActivity)
                                    requestConnect()
                                },
                                onRunDoctor = viewModel::runDiagnostics,
                                onClearCache = viewModel::clearNativeCache,
                            )

                            MainTab.APPS -> AppsScreen(
                                settings = settings,
                                apps = apps,
                                loading = appsLoading,
                                onSetSplitMode = viewModel::setSplitTunnelMode,
                                onTogglePackage = viewModel::toggleSplitPackage,
                                onClearPackages = viewModel::clearSplitPackages,
                            )

                            MainTab.SETTINGS -> SettingsScreen(
                                settings = settings,
                                engineVersion = viewModel.engineVersion,
                                onSetDesyncMode = viewModel::setDesyncMode,
                                onSetChunkSize = viewModel::setChunkSize,
                                onSetDnsAddr = viewModel::setDnsAddr,
                                onSetEnableDoh = viewModel::setEnableDoh,
                                onSetIpv4Only = viewModel::setIpv4Only,
                                onSetBlockQuic = viewModel::setBlockQuic,
                                onAddBypassDomain = viewModel::addBypassDomain,
                                onRemoveBypassDomain = viewModel::removeBypassDomain,
                                onSetTheme = viewModel::setTheme,
                                onOpenAlwaysOnVpn = {
                                    runCatching {
                                        startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
                                    }
                                },
                                onClearCache = viewModel::clearNativeCache,
                            )
                        }
                    }

                    MinimalBottomBar(
                        activeTab = activeTab,
                        onSelect = { activeTab = it },
                    )
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.getBooleanExtra(EXTRA_AUTO_CONNECT, false)) {
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
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(palette.canvas)
            .navigationBarsPadding(),
    ) {
        HairlineRule()
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(60.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            MainTab.entries.forEach { tab ->
                val selected = tab == activeTab
                val tint = if (selected) palette.inkPrimary else palette.inkMuted
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .height(60.dp)
                        .clickable(
                            interactionSource = remember { MutableInteractionSource() },
                            indication = null,
                        ) { onSelect(tab) },
                    contentAlignment = Alignment.Center,
                ) {
                    if (selected) {
                        Box(
                            modifier = Modifier
                                .align(Alignment.TopCenter)
                                .width(28.dp)
                                .height(2.dp)
                                .background(palette.inkPrimary),
                        )
                    }
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
