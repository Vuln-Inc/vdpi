package com.vulninc.vdpi.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.vulninc.vdpi.engine.DesyncMode
import com.vulninc.vdpi.engine.NativeEngineConfig
import com.vulninc.vdpi.ui.i18n.VdpiStrings
import com.vulninc.vdpi.util.isValidBypassDomain
import com.vulninc.vdpi.util.isValidDnsInput
import com.vulninc.vdpi.util.sanitizeDomainInput
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull
import java.io.IOException
import java.net.URI
import java.util.Locale

private val Context.vdpiDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "vdpi_settings",
    corruptionHandler = ReplaceFileCorruptionHandler { emptyPreferences() },
)

enum class SplitTunnelMode(val wireName: String, val label: String) {
    BYPASS_SELECTED("bypass_selected", "Bypass selected"),
    ONLY_SELECTED("only_selected", "Only selected");

    companion object {
        fun fromWire(raw: String?): SplitTunnelMode {
            if (raw == null) return BYPASS_SELECTED
            return entries.firstOrNull { it.wireName == raw || it.name == raw } ?: BYPASS_SELECTED
        }
    }
}

enum class ThemePreference(val wireName: String, val label: String) {
    SYSTEM("system", "System"),
    DARK("dark", "Dark"),
    LIGHT("light", "Light");

    companion object {
        fun fromWire(raw: String?): ThemePreference {
            if (raw == null) return SYSTEM
            return entries.firstOrNull { it.wireName == raw || it.name == raw } ?: SYSTEM
        }
    }
}

enum class AppLanguage(val code: String) {
    SYSTEM("system"),
    EN("en"),
    TR("tr");

    companion object {
        fun fromCode(raw: String?): AppLanguage {
            if (raw == null) return SYSTEM
            val normalized = raw.trim().lowercase(Locale.ROOT)
            return entries.firstOrNull {
                it.code == normalized || it.name.equals(normalized, ignoreCase = true)
            } ?: SYSTEM
        }
    }
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
    val theme: ThemePreference = ThemePreference.SYSTEM,
    val language: AppLanguage = AppLanguage.SYSTEM,
) {
    fun toNativeConfig(): NativeEngineConfig {
        val cleanedDns = dnsAddr.trim().ifEmpty { "1.1.1.1" }
        return NativeEngineConfig(
            mode = desyncMode,
            chunkSize = chunkSize.coerceIn(1, 64),
            dnsAddr = cleanedDns,
            enableDoh = enableDoh || cleanedDns.startsWith("https://", ignoreCase = true),
            ipv4Only = ipv4Only,
            blockQuic = blockQuic,
            bypassDomains = bypassDomains,
        )
    }
}

data class UpdateCheckCache(
    val dismissedUpdateVersion: String = "",
    val lastUpdateCheckEpochMs: Long = 0L,
    val cachedUpdateJson: String = "",
)

@Serializable
private data class SettingsBackupPayload(
    val version: Int = BACKUP_SCHEMA_VERSION,
    @SerialName("desync_mode") val desyncMode: String = DesyncMode.COMBO.wireName,
    @SerialName("chunk_size") val chunkSize: Int = 10,
    @SerialName("dns_addr") val dnsAddr: String = "1.1.1.1",
    @SerialName("enable_doh") val enableDoh: Boolean = true,
    @SerialName("ipv4_only") val ipv4Only: Boolean = false,
    @SerialName("block_quic") val blockQuic: Boolean = true,
    @SerialName("bypass_domains") val bypassDomains: List<String> = emptyList(),
    @SerialName("split_tunnel_mode") val splitTunnelMode: String = SplitTunnelMode.BYPASS_SELECTED.wireName,
    @SerialName("split_packages") val splitPackages: List<String> = emptyList(),
    val theme: String = ThemePreference.SYSTEM.wireName,
    val language: String = AppLanguage.SYSTEM.code,
)

private const val BACKUP_SCHEMA_VERSION = 1
private const val MAX_BACKUP_JSON_CHARS = 512 * 1024
private val PACKAGE_NAME_REGEX = Regex("^[a-zA-Z0-9_]+(\\.[a-zA-Z0-9_]+)+$")
private val KNOWN_BACKUP_KEYS = setOf(
    "desync_mode",
    "chunk_size",
    "dns_addr",
    "enable_doh",
    "ipv4_only",
    "block_quic",
    "bypass_domains",
    "split_tunnel_mode",
    "split_packages",
    "theme",
    "language",
)

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
        val LANGUAGE = stringPreferencesKey("language")
        val DISMISSED_UPDATE_VERSION = stringPreferencesKey("dismissed_update_version")
        val LAST_UPDATE_CHECK_EPOCH_MS = longPreferencesKey("last_update_check_epoch_ms")
        val CACHED_UPDATE_JSON = stringPreferencesKey("cached_update_json")
    }

    val settingsFlow: Flow<VdpiSettings> = context.vdpiDataStore.data
        .catch { err ->
            if (err is IOException) emit(emptyPreferences()) else throw err
        }
        .map { prefs ->
            val mode = prefs[Keys.DESYNC_MODE]?.let { raw ->
                DesyncMode.entries.firstOrNull { it.wireName == raw }
            } ?: DesyncMode.COMBO

            val splitMode = SplitTunnelMode.fromWire(prefs[Keys.SPLIT_MODE])
            val theme = ThemePreference.fromWire(prefs[Keys.THEME])
            val language = AppLanguage.fromCode(prefs[Keys.LANGUAGE])
            if (cachedLanguage != language) {
                writeLanguageMirror(context, language)
            }
            val dnsAddr = prefs[Keys.DNS_ADDR]?.takeIf { it.isNotBlank() } ?: "1.1.1.1"
            val enableDoh = (prefs[Keys.ENABLE_DOH] ?: true) ||
                dnsAddr.trim().startsWith("https://", ignoreCase = true)

            VdpiSettings(
                desyncMode = mode,
                chunkSize = (prefs[Keys.CHUNK_SIZE] ?: 10).coerceIn(1, 64),
                dnsAddr = dnsAddr,
                enableDoh = enableDoh,
                ipv4Only = prefs[Keys.IPV4_ONLY] ?: false,
                blockQuic = prefs[Keys.BLOCK_QUIC] ?: true,
                bypassDomains = prefs[Keys.BYPASS_DOMAINS]?.sorted() ?: emptyList(),
                splitTunnelMode = splitMode,
                splitPackages = prefs[Keys.SPLIT_PACKAGES] ?: emptySet(),
                theme = theme,
                language = language,
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
        context.vdpiDataStore.edit { prefs ->
            prefs[Keys.DNS_ADDR] = cleaned
            if (cleaned.startsWith("https://", ignoreCase = true)) {
                prefs[Keys.ENABLE_DOH] = true
            }
        }
    }

    suspend fun setEnableDoh(enabled: Boolean) {
        context.vdpiDataStore.edit { prefs ->
            val currentDns = prefs[Keys.DNS_ADDR]?.trim().orEmpty()
            prefs[Keys.ENABLE_DOH] = enabled || currentDns.startsWith("https://", ignoreCase = true)
        }
    }

    suspend fun setIpv4Only(enabled: Boolean) {
        context.vdpiDataStore.edit { it[Keys.IPV4_ONLY] = enabled }
    }

    suspend fun setBlockQuic(enabled: Boolean) {
        context.vdpiDataStore.edit { it[Keys.BLOCK_QUIC] = enabled }
    }

    suspend fun addBypassDomain(domain: String) {
        val cleaned = domain.trim().lowercase(Locale.ROOT)
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
        context.vdpiDataStore.edit { it[Keys.SPLIT_MODE] = mode.wireName }
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

    suspend fun setSplitPackages(packages: Set<String>) {
        context.vdpiDataStore.edit { it[Keys.SPLIT_PACKAGES] = packages }
    }

    suspend fun clearSplitPackages() {
        context.vdpiDataStore.edit { it[Keys.SPLIT_PACKAGES] = emptySet() }
    }

    suspend fun setTheme(theme: ThemePreference) {
        context.vdpiDataStore.edit { it[Keys.THEME] = theme.wireName }
    }

    suspend fun setLanguage(language: AppLanguage) {
        writeLanguageMirror(context, language)
        context.vdpiDataStore.edit { it[Keys.LANGUAGE] = language.code }
    }

    suspend fun applySettings(settings: VdpiSettings) {
        val cleanedDns = settings.dnsAddr.trim().ifEmpty { "1.1.1.1" }
        val normalizedEnableDoh = settings.enableDoh ||
            cleanedDns.startsWith("https://", ignoreCase = true)
        val cleanedDomains = settings.bypassDomains
            .map { sanitizeDomainInput(it) }
            .filter { isValidBypassDomain(it) }
            .toSet()
        writeLanguageMirror(context, settings.language)
        context.vdpiDataStore.edit { prefs ->
            prefs[Keys.DESYNC_MODE] = settings.desyncMode.wireName
            prefs[Keys.CHUNK_SIZE] = settings.chunkSize.coerceIn(1, 64)
            prefs[Keys.DNS_ADDR] = cleanedDns
            prefs[Keys.ENABLE_DOH] = normalizedEnableDoh
            prefs[Keys.IPV4_ONLY] = settings.ipv4Only
            prefs[Keys.BLOCK_QUIC] = settings.blockQuic
            prefs[Keys.BYPASS_DOMAINS] = cleanedDomains
            prefs[Keys.SPLIT_MODE] = settings.splitTunnelMode.wireName
            prefs[Keys.SPLIT_PACKAGES] = settings.splitPackages
            prefs[Keys.THEME] = settings.theme.wireName
            prefs[Keys.LANGUAGE] = settings.language.code
        }
    }

    val updateCacheFlow: Flow<UpdateCheckCache> = context.vdpiDataStore.data
        .catch { err ->
            if (err is IOException) emit(emptyPreferences()) else throw err
        }
        .map { prefs ->
            UpdateCheckCache(
                dismissedUpdateVersion = prefs[Keys.DISMISSED_UPDATE_VERSION].orEmpty(),
                lastUpdateCheckEpochMs = prefs[Keys.LAST_UPDATE_CHECK_EPOCH_MS] ?: 0L,
                cachedUpdateJson = prefs[Keys.CACHED_UPDATE_JSON].orEmpty(),
            )
        }

    suspend fun currentUpdateCache(): UpdateCheckCache = updateCacheFlow.first()

    suspend fun setDismissedUpdateVersion(version: String) {
        val normalized = UpdateChecker.normalizeVersionTag(version)
        context.vdpiDataStore.edit { prefs ->
            prefs[Keys.DISMISSED_UPDATE_VERSION] = normalized
        }
    }

    suspend fun recordUpdateCheckResult(epochMs: Long, cachedUpdate: ReleaseUpdateInfo?) {
        val encoded = if (cachedUpdate != null) {
            compactJson.encodeToString(ReleaseUpdateInfo.serializer(), cachedUpdate)
        } else {
            ""
        }
        context.vdpiDataStore.edit { prefs ->
            prefs[Keys.LAST_UPDATE_CHECK_EPOCH_MS] = epochMs.coerceAtLeast(0L)
            prefs[Keys.CACHED_UPDATE_JSON] = encoded
        }
    }

    fun decodeCachedUpdate(raw: String): ReleaseUpdateInfo? =
        Companion.decodeCachedUpdate(raw)

    fun exportSettingsJson(settings: VdpiSettings): String =
        Companion.exportSettingsJson(settings)

    fun parseSettingsJson(raw: String): Result<VdpiSettings> =
        Companion.parseSettingsJson(raw)

    companion object {
        private const val LANGUAGE_MIRROR_PREFS = "vdpi_language_mirror"
        private const val LANGUAGE_MIRROR_KEY = "language"

        @Volatile
        private var cachedLanguage: AppLanguage? = null

        fun readLanguageSync(context: Context): AppLanguage {
            cachedLanguage?.let { return it }
            val appContext = context.applicationContext ?: context
            val raw = runCatching {
                appContext.getSharedPreferences(LANGUAGE_MIRROR_PREFS, Context.MODE_PRIVATE)
                    .getString(LANGUAGE_MIRROR_KEY, null)
            }.getOrNull()
            return AppLanguage.fromCode(raw).also { cachedLanguage = it }
        }

        internal fun writeLanguageMirror(context: Context, language: AppLanguage) {
            cachedLanguage = language
            val appContext = context.applicationContext ?: context
            runCatching {
                appContext.getSharedPreferences(LANGUAGE_MIRROR_PREFS, Context.MODE_PRIVATE)
                    .edit()
                    .putString(LANGUAGE_MIRROR_KEY, language.code)
                    .apply()
            }
        }

        fun resolveStrings(context: Context): VdpiStrings {
            val locale = context.resources?.configuration?.locales
                ?.takeIf { !it.isEmpty }
                ?.get(0)
                ?: Locale.getDefault()
            return VdpiStrings.resolve(readLanguageSync(context), locale)
        }

        private val backupJson = Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
            prettyPrint = true
        }

        private val compactJson = Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }

        private fun redactDnsInputForError(raw: String): String {
            val trimmed = raw.trim()
            if (trimmed.contains("https://", ignoreCase = true)) {
                val lower = trimmed.lowercase(Locale.ROOT)
                if (!lower.startsWith("https://")) return "https://<redacted>"
                val parsed = runCatching { URI(trimmed) }.getOrNull()
                val host = parsed?.host?.takeIf { it.isNotBlank() && parsed.userInfo == null }
                val portSuffix = parsed?.port?.takeIf { it in 1..65535 }?.let { ":$it" }.orEmpty()
                return if (host != null) "https://$host$portSuffix/<redacted>" else "https://<redacted>"
            }
            if (trimmed.contains("http://", ignoreCase = true)) {
                return "http://<redacted>"
            }
            return trimmed.ifEmpty { "<empty>" }
        }

        fun decodeCachedUpdate(raw: String): ReleaseUpdateInfo? {
            if (raw.isBlank()) return null
            return runCatching {
                compactJson.decodeFromString(ReleaseUpdateInfo.serializer(), raw)
            }.getOrNull()
        }

        fun exportSettingsJson(settings: VdpiSettings): String {
            val cleanedDns = settings.dnsAddr.trim().takeIf { isValidDnsInput(it) } ?: "1.1.1.1"
            val cleanedDomains = settings.bypassDomains
                .map { sanitizeDomainInput(it) }
                .filter { isValidBypassDomain(it) }
                .distinct()
                .sorted()
            val cleanedPackages = settings.splitPackages
                .map { it.trim() }
                .filter { PACKAGE_NAME_REGEX.matches(it) }
                .distinct()
                .sorted()

            val payload = SettingsBackupPayload(
                version = BACKUP_SCHEMA_VERSION,
                desyncMode = settings.desyncMode.wireName,
                chunkSize = settings.chunkSize.coerceIn(1, 64),
                dnsAddr = cleanedDns,
                enableDoh = settings.enableDoh || cleanedDns.startsWith("https://", ignoreCase = true),
                ipv4Only = settings.ipv4Only,
                blockQuic = settings.blockQuic,
                bypassDomains = cleanedDomains,
                splitTunnelMode = settings.splitTunnelMode.wireName,
                splitPackages = cleanedPackages,
                theme = settings.theme.wireName,
                language = settings.language.code,
            )
            return backupJson.encodeToString(SettingsBackupPayload.serializer(), payload)
        }

        fun parseSettingsJson(raw: String): Result<VdpiSettings> = runCatching {
            val trimmed = raw.trim()
            require(trimmed.isNotEmpty()) { "Settings JSON is empty" }
            require(trimmed.length <= MAX_BACKUP_JSON_CHARS) { "Settings JSON exceeds maximum size" }

            val element = backupJson.parseToJsonElement(trimmed)
            val obj = element as? JsonObject
                ?: throw IllegalArgumentException("Settings JSON must be a JSON object")

            val hasKnownKey = obj.keys.any { it in KNOWN_BACKUP_KEYS }
            require(hasKnownKey) { "Unrecognized settings backup format" }

            obj["version"]?.let { versionElem ->
                val ver = (versionElem as? JsonPrimitive)?.takeIf { !it.isString }?.intOrNull
                    ?: throw IllegalArgumentException("Invalid backup schema version")
                require(ver in 1..BACKUP_SCHEMA_VERSION) {
                    "Unsupported backup schema version: $ver"
                }
            }

            val payload = backupJson.decodeFromJsonElement(SettingsBackupPayload.serializer(), obj)

            val modeKey = payload.desyncMode.trim()
            val desyncMode = DesyncMode.entries.firstOrNull {
                it.wireName.equals(modeKey, ignoreCase = true) ||
                    it.name.equals(modeKey, ignoreCase = true)
            } ?: throw IllegalArgumentException("Unsupported desync mode: $modeKey")

            val dns = payload.dnsAddr.trim()
            require(isValidDnsInput(dns)) { "Invalid DNS address: ${redactDnsInputForError(payload.dnsAddr)}" }
            val normalizedEnableDoh = payload.enableDoh ||
                dns.startsWith("https://", ignoreCase = true)

            val splitModeKey = payload.splitTunnelMode.trim()
            val splitMode = SplitTunnelMode.entries.firstOrNull {
                it.wireName.equals(splitModeKey, ignoreCase = true) ||
                    it.name.equals(splitModeKey, ignoreCase = true)
            } ?: throw IllegalArgumentException("Unsupported split tunnel mode: $splitModeKey")

            val sanitizedDomains = payload.bypassDomains
                .map { sanitizeDomainInput(it) }
                .filter { isValidBypassDomain(it) }
                .distinct()
                .sorted()

            val sanitizedPackages = payload.splitPackages
                .map { it.trim() }
                .filter { PACKAGE_NAME_REGEX.matches(it) }
                .toSet()

            val themeKey = payload.theme.trim()
            val theme = ThemePreference.entries.firstOrNull {
                it.wireName.equals(themeKey, ignoreCase = true) ||
                    it.name.equals(themeKey, ignoreCase = true)
            } ?: throw IllegalArgumentException("Unsupported theme preference: $themeKey")

            val langKey = payload.language.trim()
            val language = AppLanguage.entries.firstOrNull {
                it.code.equals(langKey, ignoreCase = true) ||
                    it.name.equals(langKey, ignoreCase = true)
            } ?: throw IllegalArgumentException("Unsupported language preference: $langKey")

            VdpiSettings(
                desyncMode = desyncMode,
                chunkSize = payload.chunkSize.coerceIn(1, 64),
                dnsAddr = dns,
                enableDoh = normalizedEnableDoh,
                ipv4Only = payload.ipv4Only,
                blockQuic = payload.blockQuic,
                bypassDomains = sanitizedDomains,
                splitTunnelMode = splitMode,
                splitPackages = sanitizedPackages,
                theme = theme,
                language = language,
            )
        }
    }
}
