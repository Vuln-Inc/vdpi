package com.vulninc.vdpi.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.TileService
import androidx.core.app.NotificationCompat
import com.vulninc.vdpi.MainActivity
import com.vulninc.vdpi.R
import com.vulninc.vdpi.data.SettingsRepository
import com.vulninc.vdpi.data.SplitTunnelMode
import com.vulninc.vdpi.data.VdpiSettings
import com.vulninc.vdpi.engine.NativeEngine
import com.vulninc.vdpi.engine.TelemetrySnapshot
import com.vulninc.vdpi.util.formatBytes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

enum class TunnelPhase {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    ERROR,
}

data class TunnelRuntimeSnapshot(
    val phase: TunnelPhase = TunnelPhase.DISCONNECTED,
    val errorMessage: String? = null,
    val telemetry: TelemetrySnapshot = TelemetrySnapshot(),
)

object TunnelRuntimeState {
    private val _state = MutableStateFlow(TunnelRuntimeSnapshot())
    val state: StateFlow<TunnelRuntimeSnapshot> = _state.asStateFlow()

    internal fun update(transform: (TunnelRuntimeSnapshot) -> TunnelRuntimeSnapshot) {
        _state.value = transform(_state.value)
    }
}

class VdpiVpnService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var pollJob: Job? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnelAndSelf()
                return START_NOT_STICKY
            }
            ACTION_START, null -> {
                startTunnel()
                return START_STICKY
            }
            else -> return START_NOT_STICKY
        }
    }

    private fun startTunnel() {
        ensureNotificationChannel()
        TunnelRuntimeState.update {
            it.copy(phase = TunnelPhase.CONNECTING, errorMessage = null)
        }
        requestTileSync()

        val initialNotif = buildNotification(
            title = "vdpi connecting",
            subtitle = "Starting local anti-DPI engine",
        )
        startForegroundCompat(initialNotif)

        scope.launch {
            val settings = SettingsRepository(applicationContext).current()
            val vpnInterface = establishVpnInterface(settings)
            if (vpnInterface == null) {
                TunnelRuntimeState.update {
                    it.copy(
                        phase = TunnelPhase.ERROR,
                        errorMessage = "VPN permission revoked or interface could not be created",
                    )
                }
                requestTileSync()
                stopSelf()
                return@launch
            }

            // Transfer sole TUN file descriptor ownership to the Rust engine.
            val tunFd = vpnInterface.detachFd()
            val startResult = NativeEngine.start(tunFd, settings.toNativeConfig())
            if (startResult.isFailure) {
                TunnelRuntimeState.update {
                    it.copy(
                        phase = TunnelPhase.ERROR,
                        errorMessage = startResult.exceptionOrNull()?.message ?: "Engine failed to start",
                    )
                }
                requestTileSync()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return@launch
            }

            TunnelRuntimeState.update {
                it.copy(
                    phase = TunnelPhase.CONNECTED,
                    errorMessage = null,
                    telemetry = NativeEngine.snapshot(),
                )
            }
            requestTileSync()
            startTelemetryLoop()
        }
    }

    private fun establishVpnInterface(settings: VdpiSettings) = runCatching {
        val builder = Builder()
            .setSession("vdpi")
            .setMtu(1500)
            .addAddress(TUN_IPV4_ADDR, 30)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(TUN_IPV4_DNS)
            .setBlocking(false)

        if (!settings.ipv4Only) {
            builder
                .addAddress(TUN_IPV6_ADDR, 126)
                .addRoute("::", 0)
                .addDnsServer(TUN_IPV6_DNS)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        when (settings.splitTunnelMode) {
            SplitTunnelMode.BYPASS_SELECTED -> {
                // Always exclude vdpi itself so outbound desync/DoH sockets never loop into TUN.
                safeDisallow(builder, packageName)
                settings.splitPackages.forEach { pkg ->
                    if (pkg != packageName) safeDisallow(builder, pkg)
                }
            }
            SplitTunnelMode.ONLY_SELECTED -> {
                val allowed = settings.splitPackages.filter { it != packageName }
                if (allowed.isEmpty()) {
                    // Fall back to excluding self so VPN remains usable when list is empty.
                    safeDisallow(builder, packageName)
                } else {
                    allowed.forEach { pkg -> safeAllow(builder, pkg) }
                }
            }
        }

        builder.establish()
    }.getOrNull()

    private fun safeDisallow(builder: Builder, pkg: String) {
        try {
            builder.addDisallowedApplication(pkg)
        } catch (_: PackageManager.NameNotFoundException) {
            // App was uninstalled after being saved in preferences.
        }
    }

    private fun safeAllow(builder: Builder, pkg: String) {
        try {
            builder.addAllowedApplication(pkg)
        } catch (_: PackageManager.NameNotFoundException) {
            // Ignore uninstalled packages.
        }
    }

    private fun startTelemetryLoop() {
        pollJob?.cancel()
        pollJob = scope.launch {
            val nm = getSystemService(NotificationManager::class.java)
            var tick = 0
            while (isActive) {
                val snap = NativeEngine.snapshot()
                TunnelRuntimeState.update { current ->
                    if (current.phase == TunnelPhase.CONNECTED) {
                        current.copy(telemetry = snap)
                    } else {
                        current
                    }
                }
                if (tick % 3 == 0) {
                    val subtitle = "Stage ${snap.stageNumber} · ↓ ${formatBytes(snap.bytesRx)}  ↑ ${formatBytes(snap.bytesTx)}"
                    nm.notify(
                        NOTIFICATION_ID,
                        buildNotification(title = "vdpi active", subtitle = subtitle),
                    )
                }
                tick += 1
                delay(1000L)
            }
        }
    }

    private fun stopTunnelAndSelf() {
        pollJob?.cancel()
        pollJob = null
        NativeEngine.stop()
        TunnelRuntimeState.update {
            TunnelRuntimeSnapshot(
                phase = TunnelPhase.DISCONNECTED,
                errorMessage = null,
                telemetry = NativeEngine.snapshot(),
            )
        }
        requestTileSync()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        stopTunnelAndSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        pollJob?.cancel()
        NativeEngine.stop()
        if (TunnelRuntimeState.state.value.phase != TunnelPhase.ERROR) {
            TunnelRuntimeState.update {
                it.copy(phase = TunnelPhase.DISCONNECTED, telemetry = NativeEngine.snapshot())
            }
        }
        requestTileSync()
        scope.cancel()
        super.onDestroy()
    }

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun ensureNotificationChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.notification_channel_desc)
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(title: String, subtitle: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, VdpiVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vdpi_status)
            .setContentTitle(title)
            .setContentText(subtitle)
            .setOngoing(true)
            .setSilent(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openIntent)
            .addAction(0, "Disconnect", stopIntent)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun requestTileSync() {
        runCatching {
            TileService.requestListeningState(
                applicationContext,
                ComponentName(applicationContext, VdpiTileService::class.java),
            )
        }
    }

    companion object {
        const val ACTION_START = "com.vulninc.vdpi.action.START"
        const val ACTION_STOP = "com.vulninc.vdpi.action.STOP"

        private const val CHANNEL_ID = "vdpi_tunnel_status"
        private const val NOTIFICATION_ID = 4201
        private const val TUN_IPV4_ADDR = "10.0.0.1"
        private const val TUN_IPV4_DNS = "10.0.0.2"
        private const val TUN_IPV6_ADDR = "fd00:7664:7069::1"
        private const val TUN_IPV6_DNS = "fd00:7664:7069::2"

        fun start(context: Context) {
            val intent = Intent(context, VdpiVpnService::class.java).apply {
                action = ACTION_START
            }
            context.startForegroundService(intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, VdpiVpnService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }
}
