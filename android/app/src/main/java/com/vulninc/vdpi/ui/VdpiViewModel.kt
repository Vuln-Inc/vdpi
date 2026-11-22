package com.vulninc.vdpi.ui

import android.app.Application
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class InstalledAppItem(
    val packageName: String,
    val label: String,
    val isSystem: Boolean,
    val icon: Drawable?,
)

data class DoctorUiState(
    val running: Boolean = false,
    val report: DoctorReport? = null,
)

class VdpiViewModel(application: Application) : AndroidViewModel(application) {

    private val repo = SettingsRepository(application.applicationContext)

    val settings: StateFlow<VdpiSettings> = repo.settingsFlow.stateIn(
        scope = viewModelScope,
        started = SharingStarted.Eagerly,
        initialValue = VdpiSettings(),
    )

    val tunnelState: StateFlow<TunnelRuntimeSnapshot> = TunnelRuntimeState.state

    private val _installedApps = MutableStateFlow<List<InstalledAppItem>>(emptyList())
    val installedApps: StateFlow<List<InstalledAppItem>> = _installedApps.asStateFlow()

    private val _appsLoading = MutableStateFlow(false)
    val appsLoading: StateFlow<Boolean> = _appsLoading.asStateFlow()

    private val _doctorState = MutableStateFlow(DoctorUiState())
    val doctorState: StateFlow<DoctorUiState> = _doctorState.asStateFlow()

    private val _pendingReconnect = MutableStateFlow(false)
    val pendingReconnect: StateFlow<Boolean> = _pendingReconnect.asStateFlow()

    val engineVersion: String = NativeEngine.version()

    init {
        loadInstalledApps()
    }

    private fun markDirtyIfConnected() {
        if (tunnelState.value.phase == TunnelPhase.CONNECTED) {
            _pendingReconnect.value = true
        }
    }

    fun clearPendingReconnect() {
        _pendingReconnect.value = false
    }

    fun loadInstalledApps() {
        if (_appsLoading.value) return
        viewModelScope.launch {
            _appsLoading.value = true
            val apps = withContext(Dispatchers.IO) {
                queryLaunchableApps(getApplication())
            }
            _installedApps.value = apps
            _appsLoading.value = false
        }
    }

    fun runDiagnostics() {
        if (_doctorState.value.running) return
        viewModelScope.launch {
            _doctorState.value = DoctorUiState(running = true, report = null)
            val cfg = settings.value.toNativeConfig()
            val report = withContext(Dispatchers.IO) {
                NativeEngine.runDoctor(cfg)
            }
            _doctorState.value = DoctorUiState(running = false, report = report)
        }
    }

    fun clearNativeCache() {
        viewModelScope.launch(Dispatchers.IO) {
            NativeEngine.clearCache()
        }
    }

    fun setDesyncMode(mode: DesyncMode) = viewModelScope.launch {
        repo.setDesyncMode(mode)
        markDirtyIfConnected()
    }

    fun setChunkSize(size: Int) = viewModelScope.launch {
        repo.setChunkSize(size)
        markDirtyIfConnected()
    }

    fun setDnsAddr(addr: String) = viewModelScope.launch {
        repo.setDnsAddr(addr)
        markDirtyIfConnected()
    }

    fun setEnableDoh(enabled: Boolean) = viewModelScope.launch {
        repo.setEnableDoh(enabled)
        markDirtyIfConnected()
    }

    fun setIpv4Only(enabled: Boolean) = viewModelScope.launch {
        repo.setIpv4Only(enabled)
        markDirtyIfConnected()
    }

    fun setBlockQuic(enabled: Boolean) = viewModelScope.launch {
        repo.setBlockQuic(enabled)
        markDirtyIfConnected()
    }

    fun addBypassDomain(raw: String) = viewModelScope.launch {
        val cleaned = sanitizeDomainInput(raw)
        if (cleaned.isNotEmpty()) {
            repo.addBypassDomain(cleaned)
            markDirtyIfConnected()
        }
    }

    fun removeBypassDomain(domain: String) = viewModelScope.launch {
        repo.removeBypassDomain(domain)
        markDirtyIfConnected()
    }

    fun setSplitTunnelMode(mode: SplitTunnelMode) = viewModelScope.launch {
        repo.setSplitTunnelMode(mode)
        markDirtyIfConnected()
    }

    fun toggleSplitPackage(pkg: String) = viewModelScope.launch {
        repo.toggleSplitPackage(pkg)
        markDirtyIfConnected()
    }

    fun clearSplitPackages() = viewModelScope.launch {
        repo.clearSplitPackages()
        markDirtyIfConnected()
    }

    fun setTheme(theme: ThemePreference) = viewModelScope.launch {
        repo.setTheme(theme)
    }

    private fun queryLaunchableApps(app: Application): List<InstalledAppItem> {
        val pm = app.packageManager
        val selfPkg = app.packageName
        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val resolved = pm.queryIntentActivities(launcherIntent, PackageManager.MATCH_ALL)
        val seen = HashSet<String>()
        val items = ArrayList<InstalledAppItem>(resolved.size)

        for (ri in resolved) {
            val info = ri.activityInfo?.applicationInfo ?: continue
            val pkg = info.packageName
            if (pkg == selfPkg || !seen.add(pkg)) continue
            val label = runCatching { pm.getApplicationLabel(info).toString() }.getOrDefault(pkg)
            val icon = runCatching { pm.getApplicationIcon(info) }.getOrNull()
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

        items.sortBy { it.label.lowercase() }
        return items
    }
}
