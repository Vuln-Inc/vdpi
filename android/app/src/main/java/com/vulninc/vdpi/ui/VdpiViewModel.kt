package com.vulninc.vdpi.ui

import android.app.Application
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.SystemClock
import android.widget.Toast
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.vulninc.vdpi.BuildConfig
import com.vulninc.vdpi.data.ReleaseUpdateInfo
import com.vulninc.vdpi.data.SettingsRepository
import com.vulninc.vdpi.data.SplitTunnelMode
import com.vulninc.vdpi.data.ThemePreference
import com.vulninc.vdpi.data.UpdateChecker
import com.vulninc.vdpi.data.VdpiSettings
import com.vulninc.vdpi.engine.DesyncMode
import com.vulninc.vdpi.engine.DoctorReport
import com.vulninc.vdpi.engine.NativeEngine
import com.vulninc.vdpi.util.formatStageLabel
import com.vulninc.vdpi.util.formatUptime
import com.vulninc.vdpi.util.sanitizeDomainInput
import com.vulninc.vdpi.vpn.TunnelPhase
import com.vulninc.vdpi.vpn.TunnelRuntimeSnapshot
import com.vulninc.vdpi.vpn.TunnelRuntimeState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.net.URI
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

data class VdpiUiState(
    val throughputSamples: List<Long> = emptyList(),
    val currentRateBytesPerSec: Long = 0L,
    val availableUpdate: ReleaseUpdateInfo? = null,
    val isCheckingUpdate: Boolean = false,
    val updateStatusMessage: String? = null,
    val appVersion: String = BuildConfig.VERSION_NAME,
)

private const val MAX_THROUGHPUT_SAMPLES = 24
private const val MIN_RATE_SAMPLE_DELTA_MS = 250L
private const val UPDATE_CHECK_COOLDOWN_MS = 6L * 60L * 60L * 1000L

fun appendThroughputSample(
    samples: List<Long>,
    rateBytesPerSec: Long,
    maxSamples: Int = MAX_THROUGHPUT_SAMPLES,
): List<Long> {
    val safeRate = rateBytesPerSec.coerceAtLeast(0L)
    val limit = maxSamples.coerceAtLeast(1)
    if (samples.size < limit) return samples + safeRate
    return samples.subList(samples.size - limit + 1, samples.size) + safeRate
}

private fun redactDnsForReport(rawDns: String): String {
    val trimmed = rawDns.trim().ifEmpty { "1.1.1.1" }
    val lower = trimmed.lowercase(Locale.ROOT)
    if (lower.startsWith("https://")) {
        val host = runCatching { URI(trimmed).host }.getOrNull().orEmpty()
        return if (host.isNotBlank()) "https://$host/<redacted>" else "https://<redacted>"
    }
    val isPrivateIpv4 = lower.startsWith("10.") ||
        lower.startsWith("192.168.") ||
        lower.startsWith("127.") ||
        Regex("^172\\.(1[6-9]|2\\d|3[0-1])\\.").containsMatchIn(lower)
    val isPrivateIpv6 = lower.startsWith("fc") ||
        lower.startsWith("fd") ||
        lower.startsWith("fe80:") ||
        lower == "::1"
    return if (isPrivateIpv4 || isPrivateIpv6) "<private-dns>" else trimmed
}

fun buildDiagnosticsReport(
    appVersion: String,
    engineVersion: String,
    settings: VdpiSettings,
    runtime: TunnelRuntimeSnapshot,
    doctorReport: DoctorReport?,
    androidRelease: String = Build.VERSION.RELEASE ?: "unknown",
    androidSdk: Int = Build.VERSION.SDK_INT,
): String = buildString {
    val appVerLabel = if (appVersion.startsWith("v", ignoreCase = true)) appVersion else "v$appVersion"
    val engineVerLabel = if (engineVersion.startsWith("v", ignoreCase = true)) engineVersion else "v$engineVersion"
    appendLine("vdpi Android Diagnostics Report")
    appendLine("App Version: $appVerLabel (Engine: $engineVerLabel)")
    appendLine("Android: $androidRelease (API $androidSdk)")
    appendLine("Tunnel State: ${runtime.phase.name}")
    if (runtime.phase == TunnelPhase.CONNECTED) {
        val snap = runtime.telemetry
        appendLine("Active Stage: Stage ${snap.stageNumber.coerceAtLeast(1)} (${formatStageLabel(snap.stageLabel)})")
        appendLine("Uptime: ${formatUptime(snap.uptimeSecs)}")
    }
    appendLine("Desync Mode: ${settings.desyncMode.label} (${settings.desyncMode.wireName}), chunk=${settings.chunkSize.coerceIn(1, 64)}")
    appendLine(
        "DNS: ${redactDnsForReport(settings.dnsAddr)} " +
            "(DoH: ${if (settings.enableDoh) "enabled" else "disabled"}, " +
            "IPv4-only: ${if (settings.ipv4Only) "yes" else "no"})",
    )
    appendLine("QUIC Blocking: ${if (settings.blockQuic) "enabled" else "disabled"}")
    appendLine("Bypass Domains: ${settings.bypassDomains.size} configured (redacted)")
    appendLine("Split Tunnel: ${settings.splitTunnelMode.label} (${settings.splitPackages.size} apps, redacted)")
    appendLine()
    if (doctorReport == null) {
        appendLine("Diagnostic Probes: not run yet")
    } else {
        appendLine("Diagnostic Probes: ${if (doctorReport.ok) "PASS" else "FAIL"} (${doctorReport.checks.size} checks)")
        doctorReport.checks.forEach { check ->
            val status = if (check.passed) "PASS" else "FAIL"
            val detailSuffix = check.detail.trim().takeIf { it.isNotEmpty() }?.let { " - $it" }.orEmpty()
            appendLine("- [$status] ${check.name} (${check.target}): ${check.latencyMs} ms$detailSuffix")
        }
    }
}.trimEnd()

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
    private var updateCheckJob: Job? = null
    @Volatile private var activeManualUpdateCheck: Boolean = false

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
    val appVersion: String = BuildConfig.VERSION_NAME

    private val _uiState = MutableStateFlow(VdpiUiState(appVersion = BuildConfig.VERSION_NAME))
    val uiState: StateFlow<VdpiUiState> = _uiState.asStateFlow()

    val throughputSamples: StateFlow<List<Long>> = uiState
        .map { it.throughputSamples }
        .distinctUntilChanged()
        .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    val currentRateBytesPerSec: StateFlow<Long> = uiState
        .map { it.currentRateBytesPerSec }
        .distinctUntilChanged()
        .stateIn(viewModelScope, SharingStarted.Eagerly, 0L)

    val availableUpdate: StateFlow<ReleaseUpdateInfo?> = uiState
        .map { it.availableUpdate }
        .distinctUntilChanged()
        .stateIn(viewModelScope, SharingStarted.Eagerly, null)

    val isCheckingUpdate: StateFlow<Boolean> = uiState
        .map { it.isCheckingUpdate }
        .distinctUntilChanged()
        .stateIn(viewModelScope, SharingStarted.Eagerly, false)

    val updateStatusMessage: StateFlow<String?> = uiState
        .map { it.updateStatusMessage }
        .distinctUntilChanged()
        .stateIn(viewModelScope, SharingStarted.Eagerly, null)

    private val _userMessages = MutableSharedFlow<String>(extraBufferCapacity = 4)
    val userMessages: SharedFlow<String> = _userMessages.asSharedFlow()

    init {
        loadInstalledApps()
        observeThroughput()
        checkForUpdates(manual = false)
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

    private fun observeThroughput() {
        viewModelScope.launch {
            var prevTotalBytes: Long? = null
            var prevElapsedMs: Long? = null

            tunnelState.collect { snapshot ->
                if (snapshot.phase != TunnelPhase.CONNECTED) {
                    prevTotalBytes = null
                    prevElapsedMs = null
                    _uiState.update { state ->
                        if (state.throughputSamples.isEmpty() && state.currentRateBytesPerSec == 0L) {
                            state
                        } else {
                            state.copy(
                                throughputSamples = emptyList(),
                                currentRateBytesPerSec = 0L,
                            )
                        }
                    }
                    return@collect
                }

                val tx = snapshot.telemetry.bytesTx.coerceAtLeast(0L)
                val rx = snapshot.telemetry.bytesRx.coerceAtLeast(0L)
                val totalBytes = if (tx > Long.MAX_VALUE - rx) Long.MAX_VALUE else tx + rx
                val nowMs = SystemClock.elapsedRealtime()
                val lastBytes = prevTotalBytes
                val lastMs = prevElapsedMs

                if (lastBytes == null || lastMs == null) {
                    prevTotalBytes = totalBytes
                    prevElapsedMs = nowMs
                    return@collect
                }

                if (totalBytes < lastBytes) {
                    prevTotalBytes = totalBytes
                    prevElapsedMs = nowMs
                    _uiState.update { state ->
                        if (state.throughputSamples.isEmpty() && state.currentRateBytesPerSec == 0L) {
                            state
                        } else {
                            state.copy(
                                throughputSamples = emptyList(),
                                currentRateBytesPerSec = 0L,
                            )
                        }
                    }
                    return@collect
                }

                val dtMs = nowMs - lastMs
                if (dtMs < MIN_RATE_SAMPLE_DELTA_MS) {
                    return@collect
                }

                val deltaBytes = totalBytes - lastBytes
                val rateDouble = (deltaBytes.toDouble() * 1000.0) / dtMs.toDouble()
                val rateBytesPerSec = if (!rateDouble.isFinite() || rateDouble <= 0.0) {
                    0L
                } else if (rateDouble >= Long.MAX_VALUE.toDouble()) {
                    Long.MAX_VALUE
                } else {
                    rateDouble.toLong().coerceAtLeast(0L)
                }
                prevTotalBytes = totalBytes
                prevElapsedMs = nowMs

                _uiState.update { state ->
                    state.copy(
                        throughputSamples = appendThroughputSample(
                            samples = state.throughputSamples,
                            rateBytesPerSec = rateBytesPerSec,
                            maxSamples = MAX_THROUGHPUT_SAMPLES,
                        ),
                        currentRateBytesPerSec = rateBytesPerSec,
                    )
                }
            }
        }
    }

    private fun isSameVersion(a: String, b: String): Boolean {
        val normA = UpdateChecker.normalizeVersionTag(a)
        val normB = UpdateChecker.normalizeVersionTag(b)
        return normA.isNotEmpty() && normA.equals(normB, ignoreCase = true)
    }

    fun checkForUpdates(manual: Boolean = false) {
        if (!manual && updateCheckJob?.isActive == true) return
        if (manual && activeManualUpdateCheck && updateCheckJob?.isActive == true) return

        if (manual) {
            updateCheckJob?.cancel()
            activeManualUpdateCheck = true
        }

        val job = viewModelScope.launch(start = CoroutineStart.LAZY) {
            val thisJob = coroutineContext[Job]
            try {
                val cache = repo.currentUpdateCache()
                val now = System.currentTimeMillis()
                val withinCooldown = !manual &&
                    cache.lastUpdateCheckEpochMs > 0L &&
                    now >= cache.lastUpdateCheckEpochMs &&
                    (now - cache.lastUpdateCheckEpochMs) < UPDATE_CHECK_COOLDOWN_MS

                if (withinCooldown) {
                    val cached = repo.decodeCachedUpdate(cache.cachedUpdateJson)
                    val visible = cached?.takeIf {
                        UpdateChecker.isNewerVersion(it.latestVersion, appVersion) &&
                            !isSameVersion(it.latestVersion, cache.dismissedUpdateVersion)
                    }
                    _uiState.update { it.copy(availableUpdate = visible) }
                    return@launch
                }

                _uiState.update { state ->
                    state.copy(
                        isCheckingUpdate = true,
                        updateStatusMessage = if (manual) null else state.updateStatusMessage,
                    )
                }

                val result = UpdateChecker.fetchLatestReleaseResult(appVersion)
                result.onSuccess { release ->
                    repo.recordUpdateCheckResult(System.currentTimeMillis(), release)
                    if (release == null) {
                        _uiState.update { state ->
                            state.copy(
                                availableUpdate = null,
                                isCheckingUpdate = false,
                                updateStatusMessage = if (manual) "Up to date" else state.updateStatusMessage,
                            )
                        }
                    } else {
                        val latestCache = repo.currentUpdateCache()
                        val dismissedMatch = isSameVersion(
                            release.latestVersion,
                            latestCache.dismissedUpdateVersion,
                        )
                        if (manual && dismissedMatch) {
                            repo.setDismissedUpdateVersion("")
                        }
                        val visible = if (!manual && dismissedMatch) null else release
                        _uiState.update { state ->
                            state.copy(
                                availableUpdate = visible,
                                isCheckingUpdate = false,
                                updateStatusMessage = if (manual) {
                                    "Update v${release.latestVersion} available"
                                } else {
                                    state.updateStatusMessage
                                },
                            )
                        }
                    }
                }.onFailure {
                    _uiState.update { state ->
                        state.copy(
                            isCheckingUpdate = false,
                            updateStatusMessage = if (manual) {
                                "Unable to check for updates"
                            } else {
                                state.updateStatusMessage
                            },
                        )
                    }
                }
            } finally {
                if (updateCheckJob === thisJob) {
                    if (manual) {
                        activeManualUpdateCheck = false
                    }
                    _uiState.update { it.copy(isCheckingUpdate = false) }
                }
            }
        }
        updateCheckJob = job
        job.start()
    }

    fun dismissAvailableUpdate() {
        val current = _uiState.value.availableUpdate ?: return
        _uiState.update { it.copy(availableUpdate = null) }
        viewModelScope.launch {
            repo.setDismissedUpdateVersion(current.latestVersion)
        }
    }

    fun exportSettingsJson(): String =
        SettingsRepository.exportSettingsJson(settings.value)

    suspend fun exportSettingsJsonSnapshot(): String = withContext(Dispatchers.IO) {
        SettingsRepository.exportSettingsJson(repo.current())
    }

    fun importSettingsJson(rawJson: String) {
        viewModelScope.launch {
            val parsed = withContext(Dispatchers.Default) {
                SettingsRepository.parseSettingsJson(rawJson)
            }
            if (parsed.isFailure) {
                val reason = parsed.exceptionOrNull()?.message?.takeIf { it.isNotBlank() }
                    ?: "Invalid settings JSON"
                emitStatusFeedback("Import failed: $reason")
                return@launch
            }

            val imported = parsed.getOrThrow()
            var needsReconnect = false
            mutationMutex.withLock {
                val previous = repo.current()
                repo.applySettings(imported)
                val updated = repo.current()
                val phase = tunnelPhase.value
                if (phase == TunnelPhase.CONNECTED || phase == TunnelPhase.CONNECTING) {
                    val baseline = TunnelRuntimeState.appliedSettings.value
                        ?: appliedSettings
                        ?: previous.also { appliedSettings = it }
                    val labels = computeSettingsChangeSummary(updated, baseline)
                    if (labels.isNotEmpty()) {
                        needsReconnect = true
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

            val message = if (needsReconnect) {
                "Settings imported · reconnect to apply"
            } else {
                "Settings imported"
            }
            emitStatusFeedback(message)
        }
    }

    fun formatDiagnosticsReport(): String = buildDiagnosticsReport(
        appVersion = appVersion,
        engineVersion = engineVersion,
        settings = settings.value,
        runtime = tunnelState.value,
        doctorReport = doctorState.value.report,
    )

    private suspend fun emitStatusFeedback(message: String) {
        val hasCollector = _userMessages.subscriptionCount.value > 0
        _userMessages.tryEmit(message)
        if (!hasCollector) {
            withContext(Dispatchers.Main.immediate) {
                runCatching {
                    Toast.makeText(getApplication(), message, Toast.LENGTH_SHORT).show()
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
                val nativeCleared = NativeEngine.clearCache()
                val filesDir = getApplication<Application>().filesDir
                val jsonFile = File(filesDir, "adaptive-cache.json")
                val tmpFile = File(filesDir, "adaptive-cache.tmp")
                val jsonCleared = runCatching { jsonFile.delete() || !jsonFile.exists() }.getOrDefault(false)
                val tmpCleared = runCatching { tmpFile.delete() || !tmpFile.exists() }.getOrDefault(false)
                nativeCleared && jsonCleared && tmpCleared
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
