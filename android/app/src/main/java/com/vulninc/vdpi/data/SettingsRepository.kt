package com.vulninc.vdpi.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.vulninc.vdpi.engine.DesyncMode
import com.vulninc.vdpi.engine.NativeEngineConfig
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

private val Context.vdpiDataStore: DataStore<Preferences> by preferencesDataStore(name = "vdpi_settings")

enum class SplitTunnelMode(val label: String) {
    BYPASS_SELECTED("Bypass selected"),
    ONLY_SELECTED("Only selected"),
}

enum class ThemePreference(val label: String) {
    SYSTEM("System"),
    DARK("Dark"),
    LIGHT("Light"),
}

data class VdpiSettings(
    val desyncMode: DesyncMode = DesyncMode.COMBO,
    val chunkSize: Int = 10,
    val dnsAddr: String = "1.1.1.1",
    val enableDoh: Boolean = true,
    val ipv4Only: Boolean = false,
    val blockQuic: Boolean = true,
    val bypassDomains: List<String> = emptyList(),
    val splitTunnelMode: SplitTunnelMode = SplitTunnelMode.BYPASS_SELECTED,
    val splitPackages: Set<String> = emptySet(),
    val theme: ThemePreference = ThemePreference.DARK,
) {
    fun toNativeConfig(): NativeEngineConfig = NativeEngineConfig(
        mode = desyncMode,
        chunkSize = chunkSize.coerceIn(1, 64),
        dnsAddr = dnsAddr.trim().ifEmpty { "1.1.1.1" },
        enableDoh = enableDoh,
        ipv4Only = ipv4Only,
        blockQuic = blockQuic,
        bypassDomains = bypassDomains,
    )
}

class SettingsRepository(private val context: Context) {
    private object Keys {
        val DESYNC_MODE = stringPreferencesKey("desync_mode")
        val CHUNK_SIZE = intPreferencesKey("chunk_size")
        val DNS_ADDR = stringPreferencesKey("dns_addr")
        val ENABLE_DOH = booleanPreferencesKey("enable_doh")
        val IPV4_ONLY = booleanPreferencesKey("ipv4_only")
        val BLOCK_QUIC = booleanPreferencesKey("block_quic")
        val BYPASS_DOMAINS = stringSetPreferencesKey("bypass_domains")
        val SPLIT_MODE = stringPreferencesKey("split_mode")
        val SPLIT_PACKAGES = stringSetPreferencesKey("split_packages")
        val THEME = stringPreferencesKey("theme")
    }

    val settingsFlow: Flow<VdpiSettings> = context.vdpiDataStore.data.map { prefs ->
        val mode = prefs[Keys.DESYNC_MODE]?.let { raw ->
            DesyncMode.entries.firstOrNull { it.wireName == raw }
        } ?: DesyncMode.COMBO

        val splitMode = prefs[Keys.SPLIT_MODE]?.let { raw ->
            runCatching { SplitTunnelMode.valueOf(raw) }.getOrNull()
        } ?: SplitTunnelMode.BYPASS_SELECTED

        val theme = prefs[Keys.THEME]?.let { raw ->
            runCatching { ThemePreference.valueOf(raw) }.getOrNull()
        } ?: ThemePreference.DARK

        VdpiSettings(
            desyncMode = mode,
            chunkSize = (prefs[Keys.CHUNK_SIZE] ?: 10).coerceIn(1, 64),
            dnsAddr = prefs[Keys.DNS_ADDR]?.takeIf { it.isNotBlank() } ?: "1.1.1.1",
            enableDoh = prefs[Keys.ENABLE_DOH] ?: true,
            ipv4Only = prefs[Keys.IPV4_ONLY] ?: false,
            blockQuic = prefs[Keys.BLOCK_QUIC] ?: true,
            bypassDomains = prefs[Keys.BYPASS_DOMAINS]?.sorted() ?: emptyList(),
            splitTunnelMode = splitMode,
            splitPackages = prefs[Keys.SPLIT_PACKAGES] ?: emptySet(),
            theme = theme,
        )
    }

    suspend fun current(): VdpiSettings = settingsFlow.first()

    suspend fun setDesyncMode(mode: DesyncMode) {
        context.vdpiDataStore.edit { it[Keys.DESYNC_MODE] = mode.wireName }
    }

    suspend fun setChunkSize(size: Int) {
        context.vdpiDataStore.edit { it[Keys.CHUNK_SIZE] = size.coerceIn(1, 64) }
    }

    suspend fun setDnsAddr(addr: String) {
        val cleaned = addr.trim().ifEmpty { "1.1.1.1" }
        context.vdpiDataStore.edit { it[Keys.DNS_ADDR] = cleaned }
    }

    suspend fun setEnableDoh(enabled: Boolean) {
        context.vdpiDataStore.edit { it[Keys.ENABLE_DOH] = enabled }
    }

    suspend fun setIpv4Only(enabled: Boolean) {
        context.vdpiDataStore.edit { it[Keys.IPV4_ONLY] = enabled }
    }

    suspend fun setBlockQuic(enabled: Boolean) {
        context.vdpiDataStore.edit { it[Keys.BLOCK_QUIC] = enabled }
    }

    suspend fun addBypassDomain(domain: String) {
        val cleaned = domain.trim().lowercase()
        if (cleaned.isEmpty()) return
        context.vdpiDataStore.edit { prefs ->
            val current = prefs[Keys.BYPASS_DOMAINS] ?: emptySet()
            prefs[Keys.BYPASS_DOMAINS] = current + cleaned
        }
    }

    suspend fun removeBypassDomain(domain: String) {
        context.vdpiDataStore.edit { prefs ->
            val current = prefs[Keys.BYPASS_DOMAINS] ?: emptySet()
            prefs[Keys.BYPASS_DOMAINS] = current - domain
        }
    }

    suspend fun setSplitTunnelMode(mode: SplitTunnelMode) {
        context.vdpiDataStore.edit { it[Keys.SPLIT_MODE] = mode.name }
    }

    suspend fun toggleSplitPackage(packageName: String) {
        context.vdpiDataStore.edit { prefs ->
            val current = prefs[Keys.SPLIT_PACKAGES] ?: emptySet()
            prefs[Keys.SPLIT_PACKAGES] = if (packageName in current) {
                current - packageName
            } else {
                current + packageName
            }
        }
    }

    suspend fun clearSplitPackages() {
        context.vdpiDataStore.edit { it[Keys.SPLIT_PACKAGES] = emptySet() }
    }

    suspend fun setTheme(theme: ThemePreference) {
        context.vdpiDataStore.edit { it[Keys.THEME] = theme.name }
    }
}
