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
import android.content.res.Configuration
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.LinkProperties
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
import com.vulninc.vdpi.ui.i18n.VdpiStrings
import com.vulninc.vdpi.util.formatBytes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
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
    private val networkStateLock = Any()
    private val sessionGeneration = AtomicLong(0L)
    private val telemetryWakeChannel = Channel<Unit>(Channel.CONFLATED)
    @Volatile private var transitionJob: Job? = null
    @Volatile private var pollJob: Job? = null
    @Volatile private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var networkChangeJob: Job? = null
    @Volatile private var activeObservedNetworkId: Long? = null
    @Volatile private var lastObservedPhysicalNetwork: Network? = null
    @Volatile private var committedNetworkId: Long? = null
    @Volatile private var committedIpv4Signature: String? = null
    @Volatile private var committedIpv6Signature: String? = null
    @Volatile private var appliedTunIpv6: Boolean = false
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

    private val screenOnReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != Intent.ACTION_SCREEN_ON) return
            if (!serviceActive.get()) return
            telemetryWakeChannel.trySend(Unit)
        }
    }

    override fun onCreate() {
        super.onCreate()
        activeInstance = this
        serviceActive.set(true)
        ContextCompat.registerReceiver(
            this,
            dismissReceiver,
            IntentFilter(ACTION_NOTIFICATION_DISMISSED),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        ContextCompat.registerReceiver(
            this,
            screenOnReceiver,
            IntentFilter(Intent.ACTION_SCREEN_ON),
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
                val preferred = synchronized(networkStateLock) { lastObservedPhysicalNetwork }
                scheduleStart(startId = startId, preferredPhysicalNetwork = preferred)
                return START_NOT_STICKY
            }
            ACTION_START, SERVICE_INTERFACE, null -> {
                val consentNeeded = runCatching { prepare(this) != null }.getOrDefault(true)
                if (consentNeeded) {
                    // Satisfy startForegroundService() contract on API 26-35 before stopping.
                    val strings = localizedStrings()
                    ensureNotificationChannel()
                    clearNotificationState()
                    startForegroundSafe(
                        buildNotification(
                            title = getString(R.string.app_name),
                            subtitle = strings.feedbackVpnPermissionRequired,
                            ongoing = false,
                            showReconnect = false,
                        )
                    )
                    TunnelRuntimeState.update {
                        it.copy(
                            phase = TunnelPhase.ERROR,
                            errorMessage = strings.feedbackVpnPermissionRequired,
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

    private fun scheduleStart(startId: Int, preferredPhysicalNetwork: Network? = null) {
        if (!serviceActive.get()) return
        val gen = sessionGeneration.incrementAndGet()
        pollJob?.cancel()
        pollJob = null
        ensureNotificationChannel()

        val startStrings = localizedStrings()
        val initialNotif = buildNotification(
            title = startStrings.notificationTitleConnecting,
            subtitle = startStrings.notificationSubtitleConnecting,
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
                        errorMessage = startStrings.errorBackgroundStartBlocked,
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
                    failAndStop(localizedStrings().errorBackgroundStartBlocked, startId, gen)
                    return@withLock
                }

                pollJob?.cancel()
                pollJob = null
                unregisterNetworkMonitor()
                appliedTunIpv6 = false
                NativeEngine.stop()

                ensureActive()
                if (!serviceActive.get() || sessionGeneration.get() != gen) return@withLock

                val settings = SettingsRepository(applicationContext).current()
                val cm = getSystemService(ConnectivityManager::class.java)
                val activeNetwork = preferredPhysicalNetwork
                    ?.takeIf { isUsablePhysicalNetwork(cm, it) }
                    ?: findActivePhysicalNetwork(cm)
                val hasGlobalIpv6 = activeNetwork != null && hasGlobalIpv6Connectivity(activeNetwork)
                val effectiveIpv4Only = settings.ipv4Only || !hasGlobalIpv6
                val tunIpv6Enabled = !effectiveIpv4Only
                val nativeConfig = settings.toNativeConfig().copy(
                    ipv4Only = effectiveIpv4Only,
                    mtu = TUN_MTU,
                    cachePath = File(filesDir, "adaptive-cache.json").absolutePath,
                )
                val preparedConfig = NativeEngine.prepareStart(nativeConfig)
                if (preparedConfig.isFailure) {
                    failAndStop(
                        preparedConfig.exceptionOrNull()?.message ?: localizedStrings().errorNativeEngineLoadFailed,
                        startId,
                        gen,
                    )
                    return@withLock
                }

                ensureActive()
                if (!serviceActive.get() || sessionGeneration.get() != gen) return@withLock

                val vpnInterface = establishVpnInterface(settings, effectiveIpv4Only, activeNetwork)
                if (vpnInterface == null) {
                    failAndStop(
                        localizedStrings().errorVpnInterfaceFailed,
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
                val startResult = NativeEngine.startWithEncoded(
                    tunFd = tunFd,
                    encodedConfig = preparedConfig.getOrThrow(),
                    vpnService = this@VdpiVpnService,
                )
                if (startResult.isFailure) {
                    failAndStop(
                        startResult.exceptionOrNull()?.message ?: localizedStrings().errorEngineStartFailed,
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
                if (!initialSnap.running) {
                    val lastErr = initialSnap.events.lastOrNull { it.level == "error" }?.message
                        ?: localizedStrings().errorEngineExitedImmediately
                    failAndStop(lastErr, startId, gen)
                    return@withLock
                }
                val connectedAt = System.currentTimeMillis()
                val connectedStrings = localizedStrings()
                val initialSubtitle = formatConnectedSubtitle(initialSnap, connectedStrings)
                val connectedNotif = buildNotification(
                    title = connectedStrings.notificationTitleConnected,
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

                appliedTunIpv6 = tunIpv6Enabled
                setUnderlyingNetworksSafe(activeNetwork)
                registerNetworkMonitor(sessionGen = gen, initialActive = activeNetwork)
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
        appliedTunIpv6 = false
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

    private fun isUsablePhysicalNetwork(cm: ConnectivityManager?, network: Network): Boolean {
        val caps = cm?.getNetworkCapabilities(network) ?: return false
        return !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }

    private fun findActivePhysicalNetwork(
        cm: ConnectivityManager? = getSystemService(ConnectivityManager::class.java),
    ): Network? {
        val active = cm?.activeNetwork ?: return null
        val caps = cm.getNetworkCapabilities(active) ?: return null
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return null
        return active
    }

    private fun setUnderlyingNetworksSafe(network: Network?) {
        runCatching {
            setUnderlyingNetworks(network?.let { arrayOf(it) })
        }
    }

    private fun isGlobalUnicastIpv6(addr: Inet6Address): Boolean {
        if (addr.isLinkLocalAddress || addr.isLoopbackAddress || addr.isMulticastAddress || addr.isSiteLocalAddress) {
            return false
        }
        val firstByte = addr.address.firstOrNull()?.toInt()?.and(0xFF) ?: return false
        // RFC 4291 Global Unicast IPv6 (2000::/3)
        return (firstByte and 0xE0) == 0x20
    }

    private fun hasGlobalIpv6OnLinkProperties(linkProps: LinkProperties?): Boolean {
        if (linkProps == null) return false
        val hasGlobalAddr = linkProps.linkAddresses.any { linkAddr ->
            val addr = linkAddr.address
            addr is Inet6Address && isGlobalUnicastIpv6(addr)
        }
        if (!hasGlobalAddr) return false
        return linkProps.routes.any { route ->
            route.isDefaultRoute && route.destination.address is Inet6Address
        }
    }

    private fun ipv4Signature(linkProps: LinkProperties?): String {
        if (linkProps == null) return ""
        return linkProps.linkAddresses
            .asSequence()
            .map { it.address }
            .filterIsInstance<Inet4Address>()
            .filter { !it.isLoopbackAddress && !it.isLinkLocalAddress }
            .mapNotNull { it.hostAddress }
            .sorted()
            .joinToString("|")
    }

    private fun ipv6Signature(linkProps: LinkProperties?): String {
        if (linkProps == null) return ""
        return linkProps.linkAddresses
            .asSequence()
            .map { it.address }
            .filterIsInstance<Inet6Address>()
            .filter(::isGlobalUnicastIpv6)
            .mapNotNull { it.hostAddress?.substringBefore('%') }
            .distinct()
            .sorted()
            .joinToString("|")
    }

    private fun hasGlobalIpv6Connectivity(network: Network? = null): Boolean {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return false
        val active = network ?: cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(active) ?: return false
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return false
        if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return false
        return hasGlobalIpv6OnLinkProperties(cm.getLinkProperties(active))
    }

    private fun establishVpnInterface(
        settings: VdpiSettings,
        effectiveIpv4Only: Boolean,
        activeNetwork: Network?,
    ) = runCatching {
        val builder = Builder()
            .setSession("vdpi")
            .setMtu(TUN_MTU)
            .addAddress(TUN_IPV4_ADDR, 30)
            .addDnsServer(TUN_IPV4_DNS)
            .setBlocking(false)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            builder.addRoute("0.0.0.0", 0)
            EXCLUDED_IPV4_ROUTES.forEach { (addr, prefixLen) ->
                builder.excludeRoute(IpPrefix(InetAddress.getByName(addr), prefixLen))
            }
        } else {
            PUBLIC_IPV4_ROUTES.forEach { (addr, prefixLen) ->
                builder.addRoute(addr, prefixLen)
            }
        }

        if (!effectiveIpv4Only) {
            builder
                .addAddress(TUN_IPV6_ADDR, 126)
                // Route only Global Unicast IPv6 (2000::/3) plus our virtual TUN DNS so
                // loopback (::1), ULA LANs (fc00::/7), link-local (fe80::/10), and
                // multicast (ff00::/8) remain local.
                .addRoute("2000::", 3)
                .addRoute(TUN_IPV6_DNS, 128)
                .addDnsServer(TUN_IPV6_DNS)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // Always set metered=false so Android dynamically inherits meteredness from
            // underlying networks instead of hard-locking metered=true across 5G -> Wi-Fi handoffs.
            builder.setMetered(false)
        }
        builder.setUnderlyingNetworks(activeNetwork?.let { arrayOf(it) })

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
                    // Fail closed for unselected apps: allow only vdpi itself (whose outbound
                    // engine sockets are protected via VpnService.protect) so zero unselected
                    // apps are tunneled. Abort if self-allow fails.
                    if (!safeAllow(builder, packageName)) {
                        return@runCatching null
                    }
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

    private fun registerNetworkMonitor(sessionGen: Long, initialActive: Network?) {
        unregisterNetworkMonitor()
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val initialHandle = initialActive?.networkHandle
        val initialLinkProps = initialActive?.let { cm.getLinkProperties(it) }
        val initialIpv4Sig = initialActive?.let { ipv4Signature(initialLinkProps) }
        val initialIpv6Sig = initialActive?.let { ipv6Signature(initialLinkProps) }
        synchronized(networkStateLock) {
            activeObservedNetworkId = initialHandle
            lastObservedPhysicalNetwork = initialActive
            committedNetworkId = initialHandle
            committedIpv4Signature = initialIpv4Sig
            committedIpv6Signature = initialIpv6Sig
        }
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (!serviceActive.get() || networkCallback !== this || sessionGeneration.get() != sessionGen) return
                val caps = cm.getNetworkCapabilities(network)
                if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) return
                setUnderlyingNetworksSafe(network)
                scheduleNetworkEvaluation(
                    cm = cm,
                    callback = this,
                    sessionGen = sessionGen,
                    network = network,
                    linkProperties = cm.getLinkProperties(network),
                )
            }

            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities,
            ) {
                if (!serviceActive.get() || networkCallback !== this || sessionGeneration.get() != sessionGen) return
                if (networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
                val handle = network.networkHandle
                val isCurrent = synchronized(networkStateLock) {
                    activeObservedNetworkId == null || activeObservedNetworkId == handle
                }
                if (!isCurrent) return
                setUnderlyingNetworksSafe(network)
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                if (!serviceActive.get() || networkCallback !== this || sessionGeneration.get() != sessionGen) return
                val caps = cm.getNetworkCapabilities(network)
                if (caps == null ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                    !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                ) {
                    return
                }
                scheduleNetworkEvaluation(
                    cm = cm,
                    callback = this,
                    sessionGen = sessionGen,
                    network = network,
                    linkProperties = linkProperties,
                )
            }

            override fun onLost(network: Network) {
                if (!serviceActive.get() || networkCallback !== this || sessionGeneration.get() != sessionGen) return
                val handle = network.networkHandle
                val wasCurrent = synchronized(networkStateLock) {
                    if (activeObservedNetworkId != null && activeObservedNetworkId != handle) {
                        false
                    } else {
                        networkChangeJob?.cancel()
                        networkChangeJob = null
                        activeObservedNetworkId = null
                        lastObservedPhysicalNetwork = null
                        committedNetworkId = null
                        committedIpv4Signature = null
                        committedIpv6Signature = null
                        true
                    }
                }
                if (!wasCurrent) return
                setUnderlyingNetworksSafe(null)
                if (TunnelRuntimeState.state.value.phase == TunnelPhase.CONNECTED) {
                    scope.launch {
                        if (serviceActive.get() && sessionGeneration.get() == sessionGen) {
                            NativeEngine.notifyRouteChange()
                        }
                    }
                }
            }
        }
        networkCallback = cb
        val registered = runCatching {
            cm.registerDefaultNetworkCallback(cb)
            true
        }.getOrDefault(false)
        if (!registered && networkCallback === cb) {
            networkCallback = null
        }
    }

    private fun scheduleNetworkEvaluation(
        cm: ConnectivityManager,
        callback: ConnectivityManager.NetworkCallback,
        sessionGen: Long,
        network: Network,
        linkProperties: LinkProperties?,
    ) {
        val handle = network.networkHandle
        synchronized(networkStateLock) {
            if (!serviceActive.get() || networkCallback !== callback || sessionGeneration.get() != sessionGen) {
                return
            }
            activeObservedNetworkId = handle
            lastObservedPhysicalNetwork = network
            networkChangeJob?.cancel()
            networkChangeJob = scope.launch {
                delay(NETWORK_CHANGE_DEBOUNCE_MS)
                if (!isActive ||
                    !serviceActive.get() ||
                    networkCallback !== callback ||
                    sessionGeneration.get() != sessionGen ||
                    TunnelRuntimeState.state.value.phase != TunnelPhase.CONNECTED
                ) {
                    return@launch
                }
                val caps = cm.getNetworkCapabilities(network)
                if (caps == null ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                    !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                ) {
                    return@launch
                }
                val freshLinkProps = cm.getLinkProperties(network) ?: linkProperties
                val nowIpv6 = hasGlobalIpv6OnLinkProperties(freshLinkProps)
                val nowIpv4Sig = ipv4Signature(freshLinkProps)
                val nowIpv6Sig = ipv6Signature(freshLinkProps)
                var stillCurrent = false
                var prevHandle: Long? = null
                var prevIpv4Sig: String? = null
                var prevIpv6Sig: String? = null
                synchronized(networkStateLock) {
                    if (activeObservedNetworkId == handle &&
                        networkCallback === callback &&
                        sessionGeneration.get() == sessionGen
                    ) {
                        prevHandle = committedNetworkId
                        prevIpv4Sig = committedIpv4Signature
                        prevIpv6Sig = committedIpv6Signature
                        committedNetworkId = handle
                        committedIpv4Signature = nowIpv4Sig
                        committedIpv6Signature = nowIpv6Sig
                        stillCurrent = true
                    }
                }
                if (!stillCurrent) return@launch
                setUnderlyingNetworksSafe(network)

                val userForcesIpv4Only = TunnelRuntimeState.appliedSettings.value?.ipv4Only == true
                val desiredTunIpv6 = !userForcesIpv4Only && nowIpv6
                val ipv4Changed = prevIpv4Sig != null && nowIpv4Sig.isNotEmpty() && prevIpv4Sig != nowIpv4Sig
                val ipv6Changed = prevIpv6Sig != null && nowIpv6Sig.isNotEmpty() && prevIpv6Sig != nowIpv6Sig
                if (desiredTunIpv6 != appliedTunIpv6) {
                    // Underlying network IPv6 capability diverged from the active TUN config; rebuild TUN routes
                    // with the newly observed physical network so start does not race cm.activeNetwork.
                    scheduleStart(startId = latestStartId, preferredPhysicalNetwork = network)
                } else if (prevHandle != handle || ipv4Changed || ipv6Changed) {
                    // Drain stale UDP NAT sockets and clear DNS cache while preserving learned TLS strategies.
                    NativeEngine.notifyRouteChange()
                }
            }
        }
    }

    private fun unregisterNetworkMonitor() {
        val cb = networkCallback
        networkCallback = null
        synchronized(networkStateLock) {
            networkChangeJob?.cancel()
            networkChangeJob = null
            activeObservedNetworkId = null
            lastObservedPhysicalNetwork = null
            committedNetworkId = null
            committedIpv4Signature = null
            committedIpv6Signature = null
        }
        if (cb != null) {
            runCatching {
                getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
            }
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
                        ?: localizedStrings().heroTunnelStoppedUnexpectedly
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

                // Drain any prior wake signal before sampling isInteractive so an ACTION_SCREEN_ON
                // arriving after the check stays buffered and wakes the idle sleep immediately.
                telemetryWakeChannel.tryReceive()
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
                    val loopStrings = localizedStrings()
                    val subtitle = formatConnectedSubtitle(snap, loopStrings)
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
                                title = loopStrings.notificationTitleConnected,
                                subtitle = subtitle,
                                ongoing = true,
                                showReconnect = true,
                                connectedAtMs = connectedAt,
                                strings = loopStrings,
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
                if (interactive) {
                    delay(TELEMETRY_POLL_INTERACTIVE_MS)
                } else {
                    withTimeoutOrNull(TELEMETRY_POLL_IDLE_MS) {
                        telemetryWakeChannel.receive()
                    }
                }
            }
        }
    }

    private fun stopTunnelInternal(startId: Int? = null, expectedGen: Long) {
        unregisterNetworkMonitor()
        appliedTunIpv6 = false
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

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        refreshLocalizedSurfaces(this)
    }

    override fun onRevoke() {
        scheduleStop(latestStartId)
        super.onRevoke()
    }

    override fun onDestroy() {
        if (activeInstance === this) {
            activeInstance = null
        }
        serviceActive.set(false)
        sessionGeneration.incrementAndGet()
        clearNotificationState()
        runCatching { unregisterReceiver(dismissReceiver) }
        runCatching { unregisterReceiver(screenOnReceiver) }
        unregisterNetworkMonitor()
        appliedTunIpv6 = false
        transitionJob?.cancel()
        pollJob?.cancel()
        getSystemService(NotificationManager::class.java)?.cancel(NOTIFICATION_ID)
        if (TunnelRuntimeState.state.value.phase != TunnelPhase.ERROR) {
            TunnelRuntimeState.update {
                it.copy(phase = TunnelPhase.DISCONNECTED)
            }
        }
        TunnelRuntimeState.setAppliedSettings(null)
        requestTileSync()
        scope.cancel()

        val appContext = applicationContext
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            if (!serviceActive.get()) {
                NativeEngine.stop()
                if (!serviceActive.get()) {
                    val finalSnap = NativeEngine.snapshot()
                    if (TunnelRuntimeState.state.value.phase != TunnelPhase.ERROR) {
                        TunnelRuntimeState.update {
                            it.copy(phase = TunnelPhase.DISCONNECTED, telemetry = finalSnap)
                        }
                    }
                    TunnelRuntimeState.setAppliedSettings(null)
                    requestTileAndWidgetSync(appContext)
                }
            }
        }
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

    private fun localizedStrings(): VdpiStrings =
        SettingsRepository.resolveStrings(applicationContext)

    private fun refreshNotificationForLanguage() {
        if (!serviceActive.get()) return
        val strings = localizedStrings()
        ensureNotificationChannel(applicationContext, strings)
        synchronized(notificationLock) {
            if (!serviceActive.get()) return
            val snapshot = TunnelRuntimeState.state.value
            val notif = when (snapshot.phase) {
                TunnelPhase.CONNECTED -> buildNotification(
                    title = strings.notificationTitleConnected,
                    subtitle = formatConnectedSubtitle(snapshot.telemetry, strings),
                    ongoing = true,
                    showReconnect = true,
                    connectedAtMs = connectedAtWallMs,
                    strings = strings,
                )
                TunnelPhase.CONNECTING -> buildNotification(
                    title = strings.notificationTitleConnecting,
                    subtitle = strings.notificationSubtitleConnecting,
                    ongoing = true,
                    showReconnect = false,
                    connectedAtMs = null,
                    strings = strings,
                )
                TunnelPhase.DISCONNECTED, TunnelPhase.ERROR -> null
            }
            if (notif != null) {
                lastNotification = notif
                notifySafely(notif)
            }
        }
    }

    private fun formatConnectedSubtitle(
        snap: TelemetrySnapshot,
        strings: VdpiStrings = localizedStrings(),
    ): String {
        return strings.notificationConnectedSubtitle(
            stageNumber = snap.stageNumber,
            rxText = formatBytes(snap.bytesRx),
            txText = formatBytes(snap.bytesTx),
        )
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
        ensureNotificationChannel(applicationContext, localizedStrings())
    }

    private fun buildNotification(
        title: String,
        subtitle: String,
        ongoing: Boolean = true,
        showReconnect: Boolean = false,
        connectedAtMs: Long? = null,
        strings: VdpiStrings = localizedStrings(),
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
            builder.addAction(0, strings.notificationActionDisconnect, stopPendingIntent)
            if (showReconnect) {
                builder.addAction(0, strings.notificationActionReconnect, reconnectPendingIntent)
            }
        }

        return builder.build().apply {
            if (ongoing) {
                flags = flags or Notification.FLAG_ONGOING_EVENT or Notification.FLAG_NO_CLEAR
            }
        }
    }

    private fun requestTileSync() {
        requestTileAndWidgetSync(applicationContext)
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
        private const val TELEMETRY_POLL_INTERACTIVE_MS = 1_000L
        private const val TELEMETRY_POLL_IDLE_MS = 15_000L
        private const val NETWORK_CHANGE_DEBOUNCE_MS = 400L

        // LAN, loopback, link-local, CGNAT, DS-Lite/464XLAT, multicast, and reserved IPv4 ranges excluded on API 33+.
        private val EXCLUDED_IPV4_ROUTES: List<Pair<String, Int>> = listOf(
            "0.0.0.0" to 8,
            "10.0.0.0" to 8,
            "100.64.0.0" to 10,
            "127.0.0.0" to 8,
            "169.254.0.0" to 16,
            "172.16.0.0" to 12,
            "192.0.0.0" to 24,
            "192.168.0.0" to 16,
            "224.0.0.0" to 4,
            "240.0.0.0" to 4,
        )

        // Exact public IPv4 complement of EXCLUDED_IPV4_ROUTES for API 26-32 (includes 198.18.0.0/30).
        private val PUBLIC_IPV4_ROUTES: List<Pair<String, Int>> = listOf(
            "1.0.0.0" to 8,
            "2.0.0.0" to 7,
            "4.0.0.0" to 6,
            "8.0.0.0" to 7,
            "11.0.0.0" to 8,
            "12.0.0.0" to 6,
            "16.0.0.0" to 4,
            "32.0.0.0" to 3,
            "64.0.0.0" to 3,
            "96.0.0.0" to 6,
            "100.0.0.0" to 10,
            "100.128.0.0" to 9,
            "101.0.0.0" to 8,
            "102.0.0.0" to 7,
            "104.0.0.0" to 5,
            "112.0.0.0" to 5,
            "120.0.0.0" to 6,
            "124.0.0.0" to 7,
            "126.0.0.0" to 8,
            "128.0.0.0" to 3,
            "160.0.0.0" to 5,
            "168.0.0.0" to 8,
            "169.0.0.0" to 9,
            "169.128.0.0" to 10,
            "169.192.0.0" to 11,
            "169.224.0.0" to 12,
            "169.240.0.0" to 13,
            "169.248.0.0" to 14,
            "169.252.0.0" to 15,
            "169.255.0.0" to 16,
            "170.0.0.0" to 7,
            "172.0.0.0" to 12,
            "172.32.0.0" to 11,
            "172.64.0.0" to 10,
            "172.128.0.0" to 9,
            "173.0.0.0" to 8,
            "174.0.0.0" to 7,
            "176.0.0.0" to 4,
            "192.0.1.0" to 24,
            "192.0.2.0" to 23,
            "192.0.4.0" to 22,
            "192.0.8.0" to 21,
            "192.0.16.0" to 20,
            "192.0.32.0" to 19,
            "192.0.64.0" to 18,
            "192.0.128.0" to 17,
            "192.1.0.0" to 16,
            "192.2.0.0" to 15,
            "192.4.0.0" to 14,
            "192.8.0.0" to 13,
            "192.16.0.0" to 12,
            "192.32.0.0" to 11,
            "192.64.0.0" to 10,
            "192.128.0.0" to 11,
            "192.160.0.0" to 13,
            "192.169.0.0" to 16,
            "192.170.0.0" to 15,
            "192.172.0.0" to 14,
            "192.176.0.0" to 12,
            "192.192.0.0" to 10,
            "193.0.0.0" to 8,
            "194.0.0.0" to 7,
            "196.0.0.0" to 6,
            "200.0.0.0" to 5,
            "208.0.0.0" to 4,
        )

        private val serviceActive = AtomicBoolean(false)

        @Volatile
        private var activeInstance: VdpiVpnService? = null

        private fun ensureNotificationChannel(
            context: Context,
            strings: VdpiStrings = SettingsRepository.resolveStrings(context),
        ) {
            val manager = context.getSystemService(NotificationManager::class.java) ?: return
            runCatching { manager.deleteNotificationChannel(LEGACY_CHANNEL_ID) }
            val channel = NotificationChannel(
                CHANNEL_ID,
                strings.notificationChannelName,
                NotificationManager.IMPORTANCE_DEFAULT,
            ).apply {
                description = strings.notificationChannelDesc
                setSound(null, null)
                enableVibration(false)
                enableLights(false)
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            }
            manager.createNotificationChannel(channel)
        }

        fun refreshLocalizedSurfaces(context: Context) {
            val appContext = context.applicationContext ?: context
            runCatching { ensureNotificationChannel(appContext) }
            activeInstance?.refreshNotificationForLanguage()
            requestTileAndWidgetSync(appContext)
        }

        private fun requestTileAndWidgetSync(context: Context) {
            val appContext = context.applicationContext
            runCatching {
                TileService.requestListeningState(
                    appContext,
                    ComponentName(appContext, VdpiTileService::class.java),
                )
            }
            requestWidgetSync(appContext)
        }

        private fun requestWidgetSync(context: Context) {
            runCatching {
                com.vulninc.vdpi.widget.VdpiWidgetProvider.requestUpdate(context.applicationContext)
            }
        }

        fun start(context: Context): Boolean {
            val intent = Intent(context, VdpiVpnService::class.java).apply {
                action = ACTION_START
            }
            return runCatching {
                context.startForegroundService(intent)
                true
            }.getOrElse {
                val strings = SettingsRepository.resolveStrings(context)
                TunnelRuntimeState.update {
                    it.copy(
                        phase = TunnelPhase.ERROR,
                        errorMessage = strings.errorVpnBackgroundStart,
                    )
                }
                TunnelRuntimeState.setAppliedSettings(null)
                requestWidgetSync(context)
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
                val strings = SettingsRepository.resolveStrings(context)
                TunnelRuntimeState.update {
                    it.copy(
                        phase = TunnelPhase.ERROR,
                        errorMessage = strings.errorVpnReconnect,
                    )
                }
                TunnelRuntimeState.setAppliedSettings(null)
                requestWidgetSync(context)
                false
            }
        }

        fun stop(context: Context) {
            val appContext = context.applicationContext
            if (!serviceActive.get()) {
                runCatching { appContext.stopService(Intent(appContext, VdpiVpnService::class.java)) }
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
                            requestWidgetSync(appContext)
                        }
                    }
                }
                return
            }
            val intent = Intent(appContext, VdpiVpnService::class.java).apply {
                action = ACTION_STOP
            }
            runCatching {
                appContext.startService(intent)
            }.onFailure {
                runCatching { appContext.stopService(Intent(appContext, VdpiVpnService::class.java)) }
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
                            requestWidgetSync(appContext)
                        }
                    }
                }
            }
        }
    }
}
