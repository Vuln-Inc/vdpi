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
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import java.net.Inet6Address
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
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

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
    private val transitionMutex = Mutex()
    private val sessionGeneration = AtomicLong(0L)
    private var transitionJob: Job? = null
    private var pollJob: Job? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastNetworkId: Long? = null
    private var lastHasGlobalIpv6: Boolean? = null

    @Volatile
    private var latestStartId: Int = -1

    override fun onCreate() {
        super.onCreate()
        serviceActive.set(true)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        latestStartId = startId
        when (intent?.action) {
            ACTION_STOP -> {
                scheduleStop(startId)
                return START_NOT_STICKY
            }
            ACTION_RECONNECT -> {
                scheduleStart(reconnect = true, startId = startId)
                return START_NOT_STICKY
            }
            ACTION_START, SERVICE_INTERFACE, null -> {
                if (prepare(this) != null) {
                    // Satisfy startForegroundService() contract on API 26-35 before stopping.
                    ensureNotificationChannel()
                    startForegroundSafe(
                        buildNotification(
                            title = "vdpi",
                            subtitle = "VPN permission required",
                        )
                    )
                    TunnelRuntimeState.update {
                        it.copy(
                            phase = TunnelPhase.ERROR,
                            errorMessage = "VPN permission required",
                        )
                    }
                    requestTileSync()
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    getSystemService(NotificationManager::class.java)?.cancel(NOTIFICATION_ID)
                    stopSelf(startId)
                    return START_NOT_STICKY
                }
                scheduleStart(reconnect = false, startId = startId)
                return START_NOT_STICKY
            }
            else -> return START_NOT_STICKY
        }
    }

    private fun scheduleStart(reconnect: Boolean, startId: Int) {
        val gen = sessionGeneration.incrementAndGet()
        ensureNotificationChannel()
        TunnelRuntimeState.update {
            it.copy(phase = TunnelPhase.CONNECTING, errorMessage = null)
        }
        requestTileSync()

        val initialNotif = buildNotification(
            title = if (reconnect) "vdpi reconnecting" else "vdpi starting",
            subtitle = "Starting local anti-DPI engine",
        )
        if (!startForegroundSafe(initialNotif)) {
            TunnelRuntimeState.update {
                it.copy(
                    phase = TunnelPhase.ERROR,
                    errorMessage = "Background start blocked by system",
                )
            }
            requestTileSync()
            stopSelf(startId)
            return
        }

        transitionJob?.cancel()
        transitionJob = scope.launch {
            transitionMutex.withLock {
                if (sessionGeneration.get() != gen) return@withLock

                // Re-assert foreground status inside the serialized critical section in case a
                // prior stop/fail finished tearing down while this start was queued.
                if (!startForegroundSafe(initialNotif)) {
                    failAndStop("Background start blocked by system", startId, gen)
                    return@withLock
                }

                pollJob?.cancel()
                pollJob = null
                unregisterNetworkMonitor()

                if (reconnect) {
                    NativeEngine.stop()
                }

                ensureActive()
                if (sessionGeneration.get() != gen) return@withLock

                val settings = SettingsRepository(applicationContext).current()
                val hasGlobalIpv6 = hasGlobalIpv6Connectivity()
                val effectiveIpv4Only = settings.ipv4Only || !hasGlobalIpv6
                val nativeConfig = settings.toNativeConfig().copy(
                    ipv4Only = effectiveIpv4Only,
                    mtu = TUN_MTU,
                )
                val preparedConfig = NativeEngine.prepareStart(nativeConfig)
                if (preparedConfig.isFailure) {
                    failAndStop(
                        preparedConfig.exceptionOrNull()?.message ?: "Failed to load native engine",
                        startId,
                        gen,
                    )
                    return@withLock
                }

                ensureActive()
                if (sessionGeneration.get() != gen) return@withLock

                val vpnInterface = establishVpnInterface(settings, effectiveIpv4Only)
                if (vpnInterface == null) {
                    failAndStop(
                        "VPN permission revoked or interface could not be created",
                        startId,
                        gen,
                    )
                    return@withLock
                }

                if (!isActive || sessionGeneration.get() != gen) {
                    runCatching { vpnInterface.close() }
                    return@withLock
                }

                // Transfer sole TUN file descriptor ownership to the Rust engine after library/config prep.
                val tunFd = vpnInterface.detachFd()
                val startResult = NativeEngine.startWithEncoded(tunFd, preparedConfig.getOrThrow())
                if (startResult.isFailure) {
                    failAndStop(
                        startResult.exceptionOrNull()?.message ?: "Engine failed to start",
                        startId,
                        gen,
                    )
                    return@withLock
                }

                if (!isActive || sessionGeneration.get() != gen) {
                    NativeEngine.stop()
                    return@withLock
                }

                TunnelRuntimeState.update {
                    it.copy(
                        phase = TunnelPhase.CONNECTED,
                        errorMessage = null,
                        telemetry = NativeEngine.snapshot(),
                    )
                }
                registerNetworkMonitor()
                requestTileSync()
                startTelemetryLoop(gen, startId)
            }
        }
    }

    private fun scheduleStop(startId: Int? = null) {
        val gen = sessionGeneration.incrementAndGet()
        pollJob?.cancel()
        pollJob = null
        transitionJob?.cancel()
        transitionJob = scope.launch {
            transitionMutex.withLock {
                stopTunnelInternal(startId, gen)
            }
        }
    }

    private fun failAndStop(message: String, startId: Int, expectedGen: Long) {
        unregisterNetworkMonitor()
        pollJob?.cancel()
        pollJob = null
        NativeEngine.stop()
        // If a newer start superseded this failed attempt while JNI stop ran, do not tear it down.
        if (sessionGeneration.get() != expectedGen) return
        TunnelRuntimeState.update {
            it.copy(
                phase = TunnelPhase.ERROR,
                errorMessage = message,
                telemetry = NativeEngine.snapshot(),
            )
        }
        requestTileSync()
        stopForeground(STOP_FOREGROUND_REMOVE)
        getSystemService(NotificationManager::class.java)?.cancel(NOTIFICATION_ID)
        stopSelf(startId)
    }

    private fun hasGlobalIpv6Connectivity(): Boolean {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return false
        val candidates = buildList {
            cm.activeNetwork?.let { add(it) }
            @Suppress("DEPRECATION")
            cm.allNetworks.forEach { if (!contains(it)) add(it) }
        }
        for (net in candidates) {
            val caps = cm.getNetworkCapabilities(net) ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            val linkProps = cm.getLinkProperties(net) ?: continue
            val hasGlobal = linkProps.linkAddresses.any { linkAddr ->
                val addr = linkAddr.address
                if (addr !is Inet6Address) return@any false
                if (addr.isLinkLocalAddress || addr.isLoopbackAddress || addr.isMulticastAddress || addr.isSiteLocalAddress) {
                    return@any false
                }
                val firstByte = addr.address.firstOrNull()?.toInt()?.and(0xFF) ?: return@any false
                // RFC 4291 Global Unicast IPv6 (2000::/3)
                (firstByte and 0xE0) == 0x20
            }
            if (hasGlobal) return true
        }
        return false
    }

    private fun establishVpnInterface(settings: VdpiSettings, effectiveIpv4Only: Boolean) = runCatching {
        val builder = Builder()
            .setSession("vdpi")
            .setMtu(TUN_MTU)
            .addAddress(TUN_IPV4_ADDR, 30)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(TUN_IPV4_DNS)
            .setBlocking(false)

        if (!effectiveIpv4Only) {
            builder
                .addAddress(TUN_IPV6_ADDR, 126)
                .addRoute("::", 0)
                .addDnsServer(TUN_IPV6_DNS)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val cm = getSystemService(ConnectivityManager::class.java)
            val caps = cm?.getNetworkCapabilities(cm.activeNetwork)
            val isUnmetered = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == true
            builder.setMetered(!isUnmetered)
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
                var addedCount = 0
                settings.splitPackages.forEach { pkg ->
                    if (pkg != packageName && safeAllow(builder, pkg)) {
                        addedCount += 1
                    }
                }
                if (addedCount == 0) {
                    // Fall back to excluding self so VPN never enters a self-routing loop.
                    safeDisallow(builder, packageName)
                }
            }
        }

        builder.establish()
    }.getOrNull()

    private fun safeDisallow(builder: Builder, pkg: String): Boolean {
        return try {
            builder.addDisallowedApplication(pkg)
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }

    private fun safeAllow(builder: Builder, pkg: String): Boolean {
        return try {
            builder.addAllowedApplication(pkg)
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }

    private fun registerNetworkMonitor() {
        unregisterNetworkMonitor()
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        lastNetworkId = cm.activeNetwork?.networkHandle
        lastHasGlobalIpv6 = hasGlobalIpv6Connectivity()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val handle = network.networkHandle
                val prev = lastNetworkId
                val prevIpv6 = lastHasGlobalIpv6
                val nowIpv6 = hasGlobalIpv6Connectivity()
                lastNetworkId = handle
                lastHasGlobalIpv6 = nowIpv6
                if (prev != null && prev != handle && TunnelRuntimeState.state.value.phase == TunnelPhase.CONNECTED) {
                    if (prevIpv6 != null && prevIpv6 != nowIpv6) {
                        // Underlying network changed between IPv4-only and IPv6-capable; rebuild TUN routes.
                        scheduleStart(reconnect = true, startId = latestStartId)
                    } else {
                        scope.launch {
                            // Refresh cached DNS & adaptive strategy after Wi-Fi <-> cellular switch.
                            NativeEngine.clearCache()
                        }
                    }
                }
            }
        }
        runCatching {
            cm.registerDefaultNetworkCallback(cb)
            networkCallback = cb
        }
    }

    private fun unregisterNetworkMonitor() {
        val cb = networkCallback ?: return
        networkCallback = null
        lastNetworkId = null
        lastHasGlobalIpv6 = null
        runCatching {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
        }
    }

    private fun startTelemetryLoop(sessionGen: Long, sessionStartId: Int) {
        pollJob?.cancel()
        pollJob = scope.launch {
            val nm = getSystemService(NotificationManager::class.java)
            var tick = 0
            var lastStage = -1
            while (isActive && sessionGeneration.get() == sessionGen) {
                val snap = NativeEngine.snapshot()
                // Re-check after blocking JNI snapshot so a clean stop never masquerades as ERROR.
                if (!isActive || sessionGeneration.get() != sessionGen) {
                    return@launch
                }
                if (!snap.running) {
                    val lastErr = snap.events.lastOrNull { it.level == "error" }?.message
                        ?: "Tunnel stopped unexpectedly"
                    scope.launch {
                        transitionMutex.withLock {
                            if (sessionGeneration.get() == sessionGen) {
                                failAndStop(lastErr, sessionStartId, sessionGen)
                            }
                        }
                    }
                    return@launch
                }

                TunnelRuntimeState.update { current ->
                    if (current.phase == TunnelPhase.CONNECTED && sessionGeneration.get() == sessionGen) {
                        current.copy(telemetry = snap)
                    } else {
                        current
                    }
                }

                if (snap.stageNumber != lastStage) {
                    lastStage = snap.stageNumber
                    requestTileSync()
                }

                if (tick % 3 == 0 &&
                    isActive &&
                    sessionGeneration.get() == sessionGen &&
                    TunnelRuntimeState.state.value.phase == TunnelPhase.CONNECTED
                ) {
                    val subtitle = "Stage ${snap.stageNumber} · ↓ ${formatBytes(snap.bytesRx)}  ↑ ${formatBytes(snap.bytesTx)}"
                    nm?.notify(
                        NOTIFICATION_ID,
                        buildNotification(title = "vdpi active", subtitle = subtitle),
                    )
                }
                tick += 1
                delay(1000L)
            }
        }
    }

    private fun stopTunnelInternal(startId: Int? = null, expectedGen: Long) {
        unregisterNetworkMonitor()
        pollJob?.cancel()
        pollJob = null
        NativeEngine.stop()
        // If a newer start superseded this stop while JNI stop ran, leave the new session intact.
        if (sessionGeneration.get() != expectedGen) return
        TunnelRuntimeState.update {
            TunnelRuntimeSnapshot(
                phase = TunnelPhase.DISCONNECTED,
                errorMessage = null,
                telemetry = NativeEngine.snapshot(),
            )
        }
        requestTileSync()
        stopForeground(STOP_FOREGROUND_REMOVE)
        getSystemService(NotificationManager::class.java)?.cancel(NOTIFICATION_ID)
        if (startId != null && startId >= 0) {
            stopSelf(startId)
        } else {
            stopSelf()
        }
    }

    override fun onRevoke() {
        scheduleStop(latestStartId)
        super.onRevoke()
    }

    override fun onDestroy() {
        serviceActive.set(false)
        unregisterNetworkMonitor()
        transitionJob?.cancel()
        pollJob?.cancel()
        NativeEngine.stop()
        getSystemService(NotificationManager::class.java)?.cancel(NOTIFICATION_ID)
        if (TunnelRuntimeState.state.value.phase != TunnelPhase.ERROR) {
            TunnelRuntimeState.update {
                it.copy(phase = TunnelPhase.DISCONNECTED, telemetry = NativeEngine.snapshot())
            }
        }
        requestTileSync()
        scope.cancel()
        super.onDestroy()
    }

    private fun startForegroundSafe(notification: Notification): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
            true
        } catch (_: IllegalStateException) {
            // Covers ForegroundServiceStartNotAllowedException (subclass of IllegalStateException on API 31+).
            false
        } catch (_: SecurityException) {
            false
        }
    }

    private fun ensureNotificationChannel() {
        val manager = getSystemService(NotificationManager::class.java) ?: return
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
        const val ACTION_RECONNECT = "com.vulninc.vdpi.action.RECONNECT"
        const val ACTION_STOP = "com.vulninc.vdpi.action.STOP"

        private const val CHANNEL_ID = "vdpi_tunnel_status"
        private const val NOTIFICATION_ID = 4201
        private const val TUN_MTU = 1400
        private const val TUN_IPV4_ADDR = "198.18.0.2"
        private const val TUN_IPV4_DNS = "198.18.0.1"
        private const val TUN_IPV6_ADDR = "fd00:7664:7069::1"
        private const val TUN_IPV6_DNS = "fd00:7664:7069::2"

        private val serviceActive = AtomicBoolean(false)

        fun start(context: Context): Boolean {
            val intent = Intent(context, VdpiVpnService::class.java).apply {
                action = ACTION_START
            }
            return runCatching {
                context.startForegroundService(intent)
                true
            }.getOrElse {
                TunnelRuntimeState.update {
                    it.copy(
                        phase = TunnelPhase.ERROR,
                        errorMessage = "Unable to start VPN service in background",
                    )
                }
                false
            }
        }

        fun reconnect(context: Context): Boolean {
            val intent = Intent(context, VdpiVpnService::class.java).apply {
                action = ACTION_RECONNECT
            }
            return runCatching {
                context.startForegroundService(intent)
                true
            }.getOrElse {
                TunnelRuntimeState.update {
                    it.copy(
                        phase = TunnelPhase.ERROR,
                        errorMessage = "Unable to reconnect VPN service",
                    )
                }
                false
            }
        }

        fun stop(context: Context) {
            if (!serviceActive.get()) {
                NativeEngine.stop()
                TunnelRuntimeState.update {
                    TunnelRuntimeSnapshot(
                        phase = TunnelPhase.DISCONNECTED,
                        errorMessage = null,
                        telemetry = NativeEngine.snapshot(),
                    )
                }
                return
            }
            val intent = Intent(context, VdpiVpnService::class.java).apply {
                action = ACTION_STOP
            }
            runCatching {
                context.startService(intent)
            }.onFailure {
                runCatching { context.stopService(Intent(context, VdpiVpnService::class.java)) }
                NativeEngine.stop()
                TunnelRuntimeState.update {
                    TunnelRuntimeSnapshot(
                        phase = TunnelPhase.DISCONNECTED,
                        errorMessage = null,
                        telemetry = NativeEngine.snapshot(),
                    )
                }
            }
        }
    }
}
