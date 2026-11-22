package com.vulninc.vdpi.vpn

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.service.quicksettings.PendingIntentActivityWrapper
import androidx.core.service.quicksettings.TileServiceCompat
import com.vulninc.vdpi.MainActivity

class VdpiTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        syncTile()
    }

    override fun onClick() {
        super.onClick()
        val phase = TunnelRuntimeState.state.value.phase
        if (phase == TunnelPhase.CONNECTED || phase == TunnelPhase.CONNECTING) {
            VdpiVpnService.stop(applicationContext)
            syncTile()
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
            syncTile()
        }
    }

    private fun syncTile() {
        val tile = qsTile ?: return
        val runtime = TunnelRuntimeState.state.value
        tile.label = "vdpi"
        when (runtime.phase) {
            TunnelPhase.CONNECTED -> {
                tile.state = Tile.STATE_ACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = "Stage ${runtime.telemetry.stageNumber}"
                }
            }
            TunnelPhase.CONNECTING -> {
                tile.state = Tile.STATE_ACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = "Starting"
                }
            }
            TunnelPhase.DISCONNECTED, TunnelPhase.ERROR -> {
                tile.state = Tile.STATE_INACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = "Off"
                }
            }
        }
        tile.updateTile()
    }
}
