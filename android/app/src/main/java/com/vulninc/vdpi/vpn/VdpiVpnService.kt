package com.vulninc.vdpi.vpn

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.PowerManager
import android.service.quicksettings.TileService
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
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
import java.net.Inet6Address
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

    private val _appliedSettings = MutableStateFlow<VdpiSettings?>(null)
    val appliedSettings: StateFlow<VdpiSettings?> = _appliedSettings.asStateFlow()

    internal fun update(transform: (TunnelRuntimeSnapshot) -> TunnelRuntimeSnapshot) {
        _state.value = transform(_state.value)
    }

    internal fun setAppliedSettings(settings: VdpiSettings?) {
        _appliedSettings.value = settings
    }
}

class VdpiVpnService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val transitionMutex = Mutex()
    private val notificationLock = Any()
    private val sessionGeneration = AtomicLong(0L)
    @Volatile private var transitionJob: Job? = null
    @Volatile private var pollJob: Job? = null
    @Volatile private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var lastNetworkId: Long? = null
    @Volatile private var lastHasGlobalIpv6: Boolean? = null
    @Volatile private var lastNotification: Notification? = null
    @Volatile private var connectedAtWallMs: Long? = null
    @Volatile private var repostJob: Job? = null

    @Volatile
    private var latestStartId: Int = -1

    private val openPendingIntent: PendingIntent by lazy {
        PendingIntent.getActivity(
            this,
            REQ_OPEN_APP,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    private val stopPendingIntent: PendingIntent by lazy {
        PendingIntent.getService(
            this,
            REQ_ACTION_STOP,
            Intent(this, VdpiVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    private val reconnectPendingIntent: PendingIntent by lazy {
        PendingIntent.getForegroundService(
            this,
            REQ_ACTION_RECONNECT,
            Intent(this, VdpiVpnService::class.java).apply { action = ACTION_RECONNECT },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    private val dismissPendingIntent: PendingIntent by lazy {
        PendingIntent.getBroadcast(
            this,
            REQ_NOTIFICATION_DISMISSED,
            Intent(ACTION_NOTIFICATION_DISMISSED).setPackage(packageName),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    private val dismissReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != ACTION_NOTIFICATION_DISMISSED) return
            val expectedGen = sessionGeneration.get()
            val phase = TunnelRuntimeState.state.value.phase
            if (!serviceActive.get() ||
                !canPostNotifications() ||
                (phase != TunnelPhase.CONNECTING && phase != TunnelPhase.CONNECTED)
            ) {
                return
            }
            synchronized(notificationLock) {
                repostJob?.cancel()
                repostJob = scope.launch {
                    delay(NOTIFICATION_REPOST_DELAY_MS)
                    synchronized(notificationLock) {
                        val currentPhase = TunnelRuntimeState.state.value.phase
                        val notification = lastNotification
                        if (isActive &&
                            serviceActive.get() &&
                            sessionGeneration.get() == expectedGen &&
                            (currentPhase == TunnelPhase.CONNECTING || currentPhase == TunnelPhase.CONNECTED) &&
                            notification != null
                        ) {
                            notifySafely(notification)
                        }
                    }
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        serviceActive.set(true)
        ContextCompat.registerReceiver(
            this,
            dismissReceiver,
            IntentFilter(ACTION_NOTIFICATION_DISMISSED),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        latestStartId = startId
        when (intent?.action) {
            ACTION_STOP -> {
                scheduleStop(startId)
                return START_NOT_STICKY
            }
            ACTION_RECONNECT -> {
                scheduleStart(startId = startId)
                return START_NOT_STICKY
            }
            ACTION_START, SERVICE_INTERFACE, null -> {
                val consentNeeded = runCatching { prepare(this) != null }.getOrDefault(true)
                if (consentNeeded) {
                    // Satisfy startForegroundService() contract on API 26-35 before stopping.
                    ensureNotificationChannel()
                    clearNotificationState()
                    startForegroundSafe(
                        buildNotification(
                            title = getString(R.string.app_name),
                            subtitle = "VPN permission required",
                            ongoing = false,
                            showReconnect = false,
                        )
                    )
                    TunnelRuntimeState.update {
                        it.copy(
                            phase = TunnelPhase.ERROR,
                            errorMessage = "VPN permission required",
                        )
                    }
                    TunnelRuntimeState.setAppliedSettings(null)
                    requestTileSync()
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    getSystemService(NotificationManager::class.java)?.cancel(NOTIFICATION_ID)
                    stopSelf(startId)
                    return START_NOT_STICKY
                }
                scheduleStart(startId = startId)
                return START_NOT_STICKY
            }
            else -> return START_NOT_STICKY
        }
    }

    private fun scheduleStart(startId: Int) {
        if (!serviceActive.get()) return
        val gen = sessionGeneration.incrementAndGet()
        pollJob?.cancel()
        pollJob = null
        ensureNotificationChannel()

        val initialNotif = buildNotification(
            title = getString(R.string.notification_title_connecting),
            subtitle = getString(R.string.notification_subtitle_connecting),
            ongoing = true,
            showReconnect = false,
            connectedAtMs = null,
        )

        val foregroundStarted = synchronized(notificationLock) {
            if (!serviceActive.get() || sessionGeneration.get() != gen) return
            repostJob?.cancel()
            repostJob = null
            connectedAtWallMs = null
            TunnelRuntimeState.update {
                it.copy(
                    phase = TunnelPhase.CONNECTING,
                    errorMessage = null,
                    telemetry = TelemetrySnapshot(),
                )
            }
            TunnelRuntimeState.setAppliedSettings(null)
            if (startForegroundSafe(initialNotif)) {
                lastNotification = initialNotif
                true
            } else {
                clearNotificationStateLocked()
                TunnelRuntimeState.update {
                    it.copy(
                        phase = TunnelPhase.ERROR,
                        errorMessage = "Background start blocked by system",
                    )
                }
                TunnelRuntimeState.setAppliedSettings(null)
                false
            }
        }
        requestTileSync()
        if (!foregroundStarted) {
            stopSelf(startId)
            return
        }

        transitionJob?.cancel()
        transitionJob = scope.launch {
            transitionMutex.withLock {
                if (!serviceActive.get() || sessionGeneration.get() != gen) return@withLock

                // Re-assert foreground status inside the serialized critical section in case a
                // prior stop/fail finished tearing down while this start was queued.
                val asserted = synchronized(notificationLock) {
                    if (!serviceActive.get() || sessionGeneration.get() != gen) return@withLock
                    if (startForegroundSafe(initialNotif)) {
                        lastNotification = initialNotif
                        true
                    } else {
                        false
                    }
                }
                if (!asserted) {
                    failAndStop("Background start blocked by system", startId, gen)
                    return@withLock
                }

                pollJob?.cancel()
                pollJob = null
                unregisterNetworkMonitor()
                NativeEngine.stop()

                ensureActive()
                if (!serviceActive.get() || sessionGeneration.get() != gen) return@withLock

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
                if (!serviceActive.get() || sessionGeneration.get() != gen) return@withLock

                val vpnInterface = establishVpnInterface(settings, effectiveIpv4Only)
                if (vpnInterface == null) {
                    failAndStop(
                        "VPN permission revoked or interface could not be created",
                        startId,
                        gen,
                    )
                    return@withLock
                }

                if (!isActive || !serviceActive.get() || sessionGeneration.get() != gen) {
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

                if (!isActive || !serviceActive.get() || sessionGeneration.get() != gen) {
                    NativeEngine.stop()
                    return@withLock
                }

                val initialSnap = NativeEngine.snapshot()
                val connectedAt = System.currentTimeMillis()
                val initialSubtitle = formatConnectedSubtitle(initialSnap)
                val connectedNotif = buildNotification(
                    title = getString(R.string.notification_title_connected),
                    subtitle = initialSubtitle,
                    ongoing = true,
                    showReconnect = true,
                    connectedAtMs = connectedAt,
                )

                var committed = false
                var postedInitial = false
                synchronized(notificationLock) {
                    if (isActive && serviceActive.get() && sessionGeneration.get() == gen) {
                        repostJob?.cancel()
                        repostJob = null
                        connectedAtWallMs = connectedAt
                        TunnelRuntimeState.setAppliedSettings(settings)
                        TunnelRuntimeState.update {
                            it.copy(
                                phase = TunnelPhase.CONNECTED,
                                errorMessage = null,
                                telemetry = initialSnap,
                            )
                        }
                        lastNotification = connectedNotif
                        postedInitial = notifySafely(connectedNotif)
                        committed = true
                    }
                }
                if (!committed) {
                    NativeEngine.stop()
                    return@withLock
                }

                registerNetworkMonitor()
                requestTileSync()
                startTelemetryLoop(
                    sessionGen = gen,
                    sessionStartId = startId,
                    initialPostedSubtitle = if (postedInitial) initialSubtitle else null,
                    initialStageNumber = initialSnap.stageNumber,
                )
            }
        }
    }

    private fun scheduleStop(startId: Int? = null) {
        val gen = sessionGeneration.incrementAndGet()
        clearNotificationState()
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
        val finalSnap = NativeEngine.snapshot()
        val committed = synchronized(notificationLock) {
            if (sessionGeneration.get() != expectedGen) return@synchronized false
            clearNotificationStateLocked()
            TunnelRuntimeState.update {
                it.copy(
                    phase = TunnelPhase.ERROR,
                    errorMessage = message,
                    telemetry = finalSnap,
                )
            }
            TunnelRuntimeState.setAppliedSettings(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            getSystemService(NotificationManager::class.java)?.cancel(NOTIFICATION_ID)
            true
        }
        if (!committed) return
        requestTileSync()
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
            // Leave underlyingNetworks at default (null) and mark VPN unmetered so Android
            // dynamically reflects the active Wi-Fi/Cellular network's real meteredness across handoffs.
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
                if (!serviceActive.get()) return
                val handle = network.networkHandle
                val prev = lastNetworkId
                val prevIpv6 = lastHasGlobalIpv6
                val nowIpv6 = hasGlobalIpv6Connectivity()
                lastNetworkId = handle
                lastHasGlobalIpv6 = nowIpv6
                if (prev != null && prev != handle && TunnelRuntimeState.state.value.phase == TunnelPhase.CONNECTED) {
                    if (prevIpv6 != null && prevIpv6 != nowIpv6) {
                        // Underlying network changed between IPv4-only and IPv6-capable; rebuild TUN routes.
                        scheduleStart(startId = latestStartId)
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

    private fun startTelemetryLoop(
        sessionGen: Long,
        sessionStartId: Int,
        initialPostedSubtitle: String?,
        initialStageNumber: Int,
    ) {
        pollJob?.cancel()
        pollJob = scope.launch {
            val powerManager = getSystemService(PowerManager::class.java)
            var wasInteractive = powerManager?.isInteractive ?: true
            var lastPostedSubtitle = initialPostedSubtitle
            var tick = 0
            var lastStage = initialStageNumber
            while (isActive && serviceActive.get() && sessionGeneration.get() == sessionGen) {
                val snap = NativeEngine.snapshot()
                // Re-check after blocking JNI snapshot so a clean stop never masquerades as ERROR.
                if (!isActive || !serviceActive.get() || sessionGeneration.get() != sessionGen) {
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

                val interactive = powerManager?.isInteractive ?: true
                val wokeUp = interactive && !wasInteractive
                wasInteractive = interactive

                if (interactive &&
                    (wokeUp || tick % 3 == 0) &&
                    isActive &&
                    serviceActive.get() &&
                    sessionGeneration.get() == sessionGen &&
                    TunnelRuntimeState.state.value.phase == TunnelPhase.CONNECTED
                ) {
                    val subtitle = formatConnectedSubtitle(snap)
                    if (subtitle != lastPostedSubtitle) {
                        val connectedAt = synchronized(notificationLock) {
                            if (sessionGeneration.get() == sessionGen && serviceActive.get()) {
                                connectedAtWallMs
                            } else {
                                null
                            }
                        }
                        if (connectedAt != null) {
                            val notif = buildNotification(
                                title = getString(R.string.notification_title_connected),
                                subtitle = subtitle,
                                ongoing = true,
                                showReconnect = true,
                                connectedAtMs = connectedAt,
                            )
                            val posted = synchronized(notificationLock) {
                                if (isActive &&
                                    serviceActive.get() &&
                                    sessionGeneration.get() == sessionGen &&
                                    TunnelRuntimeState.state.value.phase == TunnelPhase.CONNECTED
                                ) {
                                    lastNotification = notif
                                    notifySafely(notif)
                                } else {
                                    false
                                }
                            }
                            if (posted) {
                                lastPostedSubtitle = subtitle
                            }
                        }
                    }
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
        val finalSnap = NativeEngine.snapshot()
        val committed = synchronized(notificationLock) {
            if (sessionGeneration.get() != expectedGen) return@synchronized false
            clearNotificationStateLocked()
            TunnelRuntimeState.update {
                TunnelRuntimeSnapshot(
                    phase = TunnelPhase.DISCONNECTED,
                    errorMessage = null,
                    telemetry = finalSnap,
                )
            }
            TunnelRuntimeState.setAppliedSettings(null)
            stopForeground(STOP_FOREGROUND_REMOVE)
            getSystemService(NotificationManager::class.java)?.cancel(NOTIFICATION_ID)
            true
        }
        if (!committed) return
        requestTileSync()
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
        sessionGeneration.incrementAndGet()
        clearNotificationState()
        runCatching { unregisterReceiver(dismissReceiver) }
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
        TunnelRuntimeState.setAppliedSettings(null)
        requestTileSync()
        scope.cancel()
        super.onDestroy()
    }

    private fun clearNotificationState() {
        synchronized(notificationLock) {
            clearNotificationStateLocked()
        }
    }

    private fun clearNotificationStateLocked() {
        repostJob?.cancel()
        repostJob = null
        lastNotification = null
        connectedAtWallMs = null
    }

    private fun formatConnectedSubtitle(snap: TelemetrySnapshot): String {
        val stage = snap.stageNumber.coerceAtLeast(1)
        return "Stage $stage · ↓ ${formatBytes(snap.bytesRx)}  ↑ ${formatBytes(snap.bytesTx)}"
    }

    private fun canPostNotifications(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return true
        return ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
    }

    private fun notifySafely(notification: Notification): Boolean {
        if (!canPostNotifications()) return false
        return runCatching {
            val nm = getSystemService(NotificationManager::class.java) ?: return false
            nm.notify(NOTIFICATION_ID, notification)
            true
        }.getOrDefault(false)
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
        runCatching { manager.deleteNotificationChannel(LEGACY_CHANNEL_ID) }
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply {
            description = getString(R.string.notification_channel_desc)
            setSound(null, null)
            enableVibration(false)
            enableLights(false)
            setShowBadge(false)
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
        }
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(
        title: String,
        subtitle: String,
        ongoing: Boolean = true,
        showReconnect: Boolean = false,
        connectedAtMs: Long? = null,
    ): Notification {
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vdpi_status)
            .setContentTitle(title)
            .setContentText(subtitle)
            .setOngoing(ongoing)
            .setAutoCancel(false)
            .setSilent(true)
            .setOnlyAlertOnce(true)
            .setLocalOnly(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .setSortKey("000")
            .setContentIntent(openPendingIntent)

        if (connectedAtMs != null) {
            builder
                .setWhen(connectedAtMs)
                .setShowWhen(true)
                .setUsesChronometer(true)
        } else {
            builder
                .setShowWhen(false)
                .setUsesChronometer(false)
        }

        if (ongoing) {
            builder.setDeleteIntent(dismissPendingIntent)
            builder.addAction(0, getString(R.string.notification_action_disconnect), stopPendingIntent)
            if (showReconnect) {
                builder.addAction(0, getString(R.string.notification_action_reconnect), reconnectPendingIntent)
            }
        }

        return builder.build().apply {
            if (ongoing) {
                flags = flags or Notification.FLAG_ONGOING_EVENT or Notification.FLAG_NO_CLEAR
            }
        }
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
        private const val ACTION_NOTIFICATION_DISMISSED = "com.vulninc.vdpi.action.NOTIFICATION_DISMISSED"

        private const val CHANNEL_ID = "vdpi_tunnel_active_v2"
        private const val LEGACY_CHANNEL_ID = "vdpi_tunnel_status"
        private const val NOTIFICATION_ID = 4201
        private const val NOTIFICATION_REPOST_DELAY_MS = 250L

        private const val REQ_OPEN_APP = 0
        private const val REQ_ACTION_STOP = 1
        private const val REQ_ACTION_RECONNECT = 2
        private const val REQ_NOTIFICATION_DISMISSED = 3
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
                TunnelRuntimeState.setAppliedSettings(null)
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
                TunnelRuntimeState.setAppliedSettings(null)
                false
            }
        }

        fun stop(context: Context) {
            if (!serviceActive.get()) {
                runCatching { context.stopService(Intent(context, VdpiVpnService::class.java)) }
                CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
                    if (!serviceActive.get()) {
                        NativeEngine.stop()
                        if (!serviceActive.get()) {
                            TunnelRuntimeState.update {
                                TunnelRuntimeSnapshot(
                                    phase = TunnelPhase.DISCONNECTED,
                                    errorMessage = null,
                                    telemetry = NativeEngine.snapshot(),
                                )
                            }
                            TunnelRuntimeState.setAppliedSettings(null)
                        }
                    }
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
                CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
                    if (!serviceActive.get()) {
                        NativeEngine.stop()
                        if (!serviceActive.get()) {
                            TunnelRuntimeState.update {
                                TunnelRuntimeSnapshot(
                                    phase = TunnelPhase.DISCONNECTED,
                                    errorMessage = null,
                                    telemetry = NativeEngine.snapshot(),
                                )
                            }
                            TunnelRuntimeState.setAppliedSettings(null)
                        }
                    }
                }
            }
        }
    }
}
