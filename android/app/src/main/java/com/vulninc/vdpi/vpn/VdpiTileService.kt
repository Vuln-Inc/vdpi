package com.vulninc.vdpi.vpn

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.service.quicksettings.PendingIntentActivityWrapper
import androidx.core.service.quicksettings.TileServiceCompat
import com.vulninc.vdpi.MainActivity
import com.vulninc.vdpi.data.SettingsRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

class VdpiTileService : TileService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var collectJob: Job? = null

    override fun onStartListening() {
        super.onStartListening()
        syncTile(TunnelRuntimeState.state.value)
        collectJob?.cancel()
        val langFlow = SettingsRepository(applicationContext).settingsFlow
            .map { it.language }
            .distinctUntilChanged()
        collectJob = scope.launch {
            combine(TunnelRuntimeState.state, langFlow) { runtime, _ -> runtime }
                .collect { runtime ->
                    syncTile(runtime)
                }
        }
    }

    override fun onStopListening() {
        collectJob?.cancel()
        collectJob = null
        super.onStopListening()
    }

    override fun onDestroy() {
        collectJob?.cancel()
        scope.cancel()
        super.onDestroy()
    }

    override fun onClick() {
        super.onClick()
        val action = { handleToggle() }
        if (isLocked) {
            unlockAndRun(action)
        } else {
            action()
        }
    }

    private fun handleToggle() {
        val phase = TunnelRuntimeState.state.value.phase
        if (phase == TunnelPhase.CONNECTED || phase == TunnelPhase.CONNECTING) {
            VdpiVpnService.stop(applicationContext)
            return
        }

        val prepareIntent = VpnService.prepare(applicationContext)
        if (prepareIntent != null) {
            val launch = Intent(applicationContext, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra(MainActivity.EXTRA_AUTO_CONNECT, true)
            }
            val wrapper = PendingIntentActivityWrapper(
                applicationContext,
                10,
                launch,
                0,
                false,
            )
            TileServiceCompat.startActivityAndCollapse(this, wrapper)
        } else {
            VdpiVpnService.start(applicationContext)
        }
    }

    private fun syncTile(runtime: TunnelRuntimeSnapshot) {
        val tile = qsTile ?: return
        val strings = SettingsRepository.resolveStrings(applicationContext)
        tile.label = "vdpi"
        when (runtime.phase) {
            TunnelPhase.CONNECTED -> {
                tile.state = Tile.STATE_ACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = strings.tileStage(runtime.telemetry.stageNumber)
                }
            }
            TunnelPhase.CONNECTING -> {
                tile.state = Tile.STATE_ACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = strings.tileStarting
                }
            }
            TunnelPhase.DISCONNECTED, TunnelPhase.ERROR -> {
                tile.state = Tile.STATE_INACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = strings.tileOff
                }
            }
        }
        tile.updateTile()
    }
}
