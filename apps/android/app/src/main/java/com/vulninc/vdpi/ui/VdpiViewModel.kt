package com.vulninc.vdpi.ui

import android.app.Application
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.vulninc.vdpi.BuildConfig
import com.vulninc.vdpi.data.SettingsRepository
import com.vulninc.vdpi.data.SplitTunnelMode
import com.vulninc.vdpi.data.ThemePreference
import com.vulninc.vdpi.data.VdpiSettings
import com.vulninc.vdpi.engine.DesyncMode
import com.vulninc.vdpi.engine.DoctorReport
import com.vulninc.vdpi.engine.NativeEngine
import com.vulninc.vdpi.util.sanitizeDomainInput
import com.vulninc.vdpi.vpn.TunnelPhase
import com.vulninc.vdpi.vpn.TunnelRuntimeSnapshot
import com.vulninc.vdpi.vpn.TunnelRuntimeState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.Locale
import kotlin.math.roundToInt

data class InstalledAppItem(
    val packageName: String,
    val label: String,
    val isSystem: Boolean,
    val icon: ImageBitmap?,
)

data class DoctorUiState(
    val running: Boolean = false,
    val report: DoctorReport? = null,
)

fun computeSettingsChangeSummary(current: VdpiSettings, baseline: VdpiSettings): List<String> = buildList {
    if (current.desyncMode != baseline.desyncMode) add("Mode")
    if (current.chunkSize.coerceIn(1, 64) != baseline.chunkSize.coerceIn(1, 64)) add("Chunk")
    val currentDns = current.dnsAddr.trim().ifBlank { "1.1.1.1" }
    val baselineDns = baseline.dnsAddr.trim().ifBlank { "1.1.1.1" }
    if (currentDns != baselineDns) add("DNS")
    if (current.enableDoh != baseline.enableDoh) add("DoH")
    if (current.ipv4Only != baseline.ipv4Only) add("IPv4")
    if (current.blockQuic != baseline.blockQuic) add("QUIC")
    if (current.bypassDomains.toSet() != baseline.bypassDomains.toSet()) add("Bypass")
    if (current.splitTunnelMode != baseline.splitTunnelMode || current.splitPackages != baseline.splitPackages) {
        add("Apps")
    }
}

class VdpiViewModel(application: Application) : AndroidViewModel(application) {

    private val repo = SettingsRepository(application.applicationContext)
    private val mutationMutex = Mutex()
    private var appliedSettings: VdpiSettings? = null

    val settings: StateFlow<VdpiSettings> = repo.settingsFlow.stateIn(
        scope = viewModelScope,
        started = SharingStarted.Eagerly,
        initialValue = VdpiSettings(),
    )

    val tunnelState: StateFlow<TunnelRuntimeSnapshot> = TunnelRuntimeState.state

    val tunnelPhase: StateFlow<TunnelPhase> = tunnelState
        .map { it.phase }
        .distinctUntilChanged()
        .stateIn(viewModelScope, SharingStarted.Eagerly, tunnelState.value.phase)

    private val _installedApps = MutableStateFlow<List<InstalledAppItem>>(emptyList())
    val installedApps: StateFlow<List<InstalledAppItem>> = _installedApps.asStateFlow()

    private val _appsLoading = MutableStateFlow(false)
    val appsLoading: StateFlow<Boolean> = _appsLoading.asStateFlow()

    private val _doctorState = MutableStateFlow(DoctorUiState())
    val doctorState: StateFlow<DoctorUiState> = _doctorState.asStateFlow()

    private val _pendingReconnect = MutableStateFlow(false)
    val pendingReconnect: StateFlow<Boolean> = _pendingReconnect.asStateFlow()

    private val _reconnectPopupVisible = MutableStateFlow(false)
    val reconnectPopupVisible: StateFlow<Boolean> = _reconnectPopupVisible.asStateFlow()

    private val _pendingChangeSummary = MutableStateFlow("")
    val pendingChangeSummary: StateFlow<String> = _pendingChangeSummary.asStateFlow()

    // Never load JNI synchronously on the main thread during ViewModel creation.
    val engineVersion: String = BuildConfig.VERSION_NAME

    init {
        loadInstalledApps()
        viewModelScope.launch {
            var prevPhase: TunnelPhase? = null
            combine(tunnelPhase, TunnelRuntimeState.appliedSettings) { phase, applied ->
                phase to applied
            }.collect { (curr, applied) ->
                mutationMutex.withLock {
                    when (curr) {
                        TunnelPhase.CONNECTED -> {
                            val current = repo.current()
                            if (tunnelPhase.value == TunnelPhase.CONNECTED) {
                                val baseline = applied ?: appliedSettings ?: current
                                appliedSettings = baseline
                                val labels = computeSettingsChangeSummary(current, baseline)
                                if (labels.isNotEmpty()) {
                                    val shouldReveal = prevPhase != TunnelPhase.CONNECTING || !_pendingReconnect.value
                                    _pendingReconnect.value = true
                                    if (shouldReveal) {
                                        _reconnectPopupVisible.value = true
                                    }
                                    _pendingChangeSummary.value = labels.joinToString(", ")
                                } else {
                                    clearPendingReconnect()
                                }
                            }
                        }
                        TunnelPhase.CONNECTING -> {
                            if (prevPhase != TunnelPhase.CONNECTING) {
                                appliedSettings = null
                                clearPendingReconnect()
                            }
                        }
                        TunnelPhase.DISCONNECTED, TunnelPhase.ERROR -> {
                            appliedSettings = null
                            clearPendingReconnect()
                        }
                    }
                    prevPhase = curr
                }
            }
        }
    }

    private fun mutateRuntimeSetting(
        isNoOp: (VdpiSettings) -> Boolean,
        mutate: suspend () -> Unit,
    ): Job = viewModelScope.launch {
        mutationMutex.withLock {
            val previous = repo.current()
            if (isNoOp(previous)) return@withLock
            mutate()
            val updated = repo.current()
            val phase = tunnelPhase.value
            if (phase == TunnelPhase.CONNECTED || phase == TunnelPhase.CONNECTING) {
                val baseline = TunnelRuntimeState.appliedSettings.value
                    ?: appliedSettings
                    ?: previous.also { appliedSettings = it }
                val labels = computeSettingsChangeSummary(updated, baseline)
                if (labels.isNotEmpty()) {
                    _pendingReconnect.value = true
                    _reconnectPopupVisible.value = true
                    _pendingChangeSummary.value = labels.joinToString(", ")
                } else {
                    clearPendingReconnect()
                }
            } else {
                appliedSettings = null
                clearPendingReconnect()
            }
        }
    }

    fun dismissReconnectPopup() {
        _reconnectPopupVisible.value = false
    }

    fun clearPendingReconnect() {
        _pendingReconnect.value = false
        _reconnectPopupVisible.value = false
        _pendingChangeSummary.value = ""
    }

    fun resetForExplicitReconnect() {
        appliedSettings = null
        clearPendingReconnect()
        viewModelScope.launch {
            mutationMutex.withLock {
                appliedSettings = null
                clearPendingReconnect()
            }
        }
    }

    fun loadInstalledApps() {
        if (_appsLoading.value) return
        viewModelScope.launch {
            _appsLoading.value = true
            try {
                val apps = withContext(Dispatchers.Default) {
                    queryLaunchableApps(getApplication())
                }
                if (apps != null) {
                    _installedApps.value = apps
                }
            } finally {
                _appsLoading.value = false
            }
        }
    }

    fun runDiagnostics() {
        if (_doctorState.value.running) return
        viewModelScope.launch {
            _doctorState.value = DoctorUiState(running = true, report = null)
            try {
                val cfg = repo.current().toNativeConfig()
                val report = withContext(Dispatchers.IO) {
                    NativeEngine.runDoctor(cfg)
                }
                _doctorState.value = DoctorUiState(running = false, report = report)
            } catch (e: CancellationException) {
                _doctorState.value = _doctorState.value.copy(running = false)
                throw e
            }
        }
    }

    fun clearNativeCache(onResult: (Boolean) -> Unit = {}) {
        viewModelScope.launch {
            val cleared = withContext(Dispatchers.IO) {
                NativeEngine.clearCache()
            }
            onResult(cleared)
        }
    }

    fun setDesyncMode(mode: DesyncMode) = mutateRuntimeSetting(
        isNoOp = { it.desyncMode == mode },
    ) {
        repo.setDesyncMode(mode)
    }

    fun setChunkSize(size: Int) {
        val clamped = size.coerceIn(1, 64)
        mutateRuntimeSetting(isNoOp = { it.chunkSize == clamped }) {
            repo.setChunkSize(clamped)
        }
    }

    fun setDnsAddr(addr: String) {
        val normalized = addr.trim().ifBlank { "1.1.1.1" }
        mutateRuntimeSetting(isNoOp = { it.dnsAddr.trim().ifBlank { "1.1.1.1" } == normalized }) {
            repo.setDnsAddr(normalized)
        }
    }

    fun setEnableDoh(enabled: Boolean) = mutateRuntimeSetting(
        isNoOp = { it.enableDoh == enabled },
    ) {
        repo.setEnableDoh(enabled)
    }

    fun setIpv4Only(enabled: Boolean) = mutateRuntimeSetting(
        isNoOp = { it.ipv4Only == enabled },
    ) {
        repo.setIpv4Only(enabled)
    }

    fun setBlockQuic(enabled: Boolean) = mutateRuntimeSetting(
        isNoOp = { it.blockQuic == enabled },
    ) {
        repo.setBlockQuic(enabled)
    }

    fun addBypassDomain(raw: String) {
        val cleaned = sanitizeDomainInput(raw)
        if (cleaned.isEmpty()) return
        mutateRuntimeSetting(isNoOp = { cleaned in it.bypassDomains }) {
            repo.addBypassDomain(cleaned)
        }
    }

    fun removeBypassDomain(domain: String) = mutateRuntimeSetting(
        isNoOp = { domain !in it.bypassDomains },
    ) {
        repo.removeBypassDomain(domain)
    }

    fun setSplitTunnelMode(mode: SplitTunnelMode) = mutateRuntimeSetting(
        isNoOp = { it.splitTunnelMode == mode },
    ) {
        repo.setSplitTunnelMode(mode)
    }

    fun toggleSplitPackage(pkg: String) = mutateRuntimeSetting(
        isNoOp = { pkg.isBlank() },
    ) {
        repo.toggleSplitPackage(pkg)
    }

    fun restoreSplitPackages(packages: Set<String>) = mutateRuntimeSetting(
        isNoOp = { it.splitPackages == packages },
    ) {
        repo.setSplitPackages(packages)
    }

    fun clearSplitPackages() = mutateRuntimeSetting(
        isNoOp = { it.splitPackages.isEmpty() },
    ) {
        repo.clearSplitPackages()
    }

    fun setTheme(theme: ThemePreference) = viewModelScope.launch {
        if (repo.current().theme == theme) return@launch
        repo.setTheme(theme)
    }

    private fun queryLaunchableApps(app: Application): List<InstalledAppItem>? {
        val pm = app.packageManager
        val selfPkg = app.packageName
        val density = app.resources.displayMetrics.density
        val iconPx = (36f * density).roundToInt().coerceIn(72, 144)

        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val resolved = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.queryIntentActivities(
                    launcherIntent,
                    PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_ALL.toLong()),
                )
            } else {
                @Suppress("DEPRECATION")
                pm.queryIntentActivities(launcherIntent, PackageManager.MATCH_ALL)
            }
        }.getOrElse { return null }

        val seen = HashSet<String>()
        val items = ArrayList<InstalledAppItem>(resolved.size)

        for (ri in resolved) {
            val info = ri.activityInfo?.applicationInfo ?: continue
            val pkg = info.packageName
            if (pkg == selfPkg || !seen.add(pkg)) continue
            val label = runCatching { pm.getApplicationLabel(info).toString() }.getOrDefault(pkg)
            val icon = runCatching {
                pm.getApplicationIcon(info).toBitmap(iconPx, iconPx).asImageBitmap()
            }.getOrNull()
            val isSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            items.add(
                InstalledAppItem(
                    packageName = pkg,
                    label = label,
                    isSystem = isSystem,
                    icon = icon,
                )
            )
        }

        items.sortBy { it.label.lowercase(Locale.ROOT) }
        return items
    }
}
