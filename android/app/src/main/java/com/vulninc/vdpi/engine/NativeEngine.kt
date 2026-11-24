package com.vulninc.vdpi.engine

import com.vulninc.vdpi.BuildConfig
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
enum class DesyncMode(val wireName: String, val label: String, val summary: String) {
    @SerialName("combo")
    COMBO("combo", "Combo", "4-record TLS split + adaptive 7-stage auto-heal"),

    @SerialName("tls-record")
    TLS_RECORD("tls-record", "TLS Record", "Split ClientHello across two RFC TLS records"),

    @SerialName("fragment")
    FRAGMENT("fragment", "Fragment", "Single outer TLS record sliced at SNI boundaries"),

    @SerialName("split")
    SPLIT("split", "Split", "Initial chunk-byte TCP split on first flight"),
}

@Serializable
data class NativeEngineConfig(
    val mode: DesyncMode = DesyncMode.COMBO,
    @SerialName("chunk_size") val chunkSize: Int = 10,
    @SerialName("dns_addr") val dnsAddr: String = "1.1.1.1",
    @SerialName("enable_doh") val enableDoh: Boolean = true,
    @SerialName("ipv4_only") val ipv4Only: Boolean = false,
    @SerialName("block_quic") val blockQuic: Boolean = true,
    @SerialName("timeout_ms") val timeoutMs: Long = 8000L,
    val mtu: Int = 1400,
    @SerialName("bypass_domains") val bypassDomains: List<String> = emptyList(),
    @SerialName("cache_path") val cachePath: String? = null,
)

typealias TunnelConfig = NativeEngineConfig

@Serializable
data class EngineEvent(
    val seq: Long = 0L,
    @SerialName("ts_ms") val tsMs: Long = 0L,
    val level: String = "info",
    val tag: String = "tun",
    val message: String = "",
)

@Serializable
data class TelemetrySnapshot(
    val running: Boolean = false,
    @SerialName("uptime_secs") val uptimeSecs: Long = 0L,
    @SerialName("active_connections") val activeConnections: Int = 0,
    @SerialName("total_connections") val totalConnections: Long = 0L,
    @SerialName("bytes_tx") val bytesTx: Long = 0L,
    @SerialName("bytes_rx") val bytesRx: Long = 0L,
    @SerialName("tls_handshakes") val tlsHandshakes: Long = 0L,
    @SerialName("auto_heal_escalations") val autoHealEscalations: Long = 0L,
    @SerialName("dns_queries") val dnsQueries: Long = 0L,
    @SerialName("quic_blocked") val quicBlocked: Long = 0L,
    @SerialName("udp_flows_active") val udpFlowsActive: Long = 0L,
    @SerialName("learned_hosts") val learnedHosts: Int = 0,
    @SerialName("stage_number") val stageNumber: Int = 1,
    @SerialName("stage_label") val stageLabel: String = "ComboMultiRecord",
    @SerialName("dns_addr") val dnsAddr: String = "1.1.1.1",
    @SerialName("doh_enabled") val dohEnabled: Boolean = true,
    val events: List<EngineEvent> = emptyList(),
)

@Serializable
data class DoctorCheck(
    val name: String = "",
    val target: String = "",
    val passed: Boolean = false,
    @SerialName("latency_ms") val latencyMs: Long = 0L,
    val detail: String = "",
)

@Serializable
data class DoctorReport(
    val ok: Boolean = false,
    val checks: List<DoctorCheck> = emptyList(),
)

object NativeEngine {
    val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    @Volatile
    private var loaded = false

    private fun ensureLoaded() {
        if (!loaded) {
            synchronized(this) {
                if (!loaded) {
                    System.loadLibrary("vdpi_android")
                    loaded = true
                }
            }
        }
    }

    @JvmStatic
    private external fun nativeStart(tunFd: Int, configJson: String): String

    @JvmStatic
    private external fun nativeStop()

    @JvmStatic
    private external fun nativeSnapshotJson(): String

    @JvmStatic
    private external fun nativeRunDoctor(configJson: String): String

    @JvmStatic
    private external fun nativeClearCache()

    @JvmStatic
    private external fun nativeVersion(): String

    fun encodeConfig(config: NativeEngineConfig): String =
        json.encodeToString(NativeEngineConfig.serializer(), config)

    fun decodeSnapshot(raw: String): TelemetrySnapshot =
        runCatching { json.decodeFromString(TelemetrySnapshot.serializer(), raw) }
            .getOrDefault(TelemetrySnapshot())

    fun decodeDoctorReport(raw: String): DoctorReport =
        runCatching { json.decodeFromString(DoctorReport.serializer(), raw) }
            .getOrDefault(DoctorReport())

    fun prepareStart(config: NativeEngineConfig): Result<String> {
        return runCatching {
            ensureLoaded()
            encodeConfig(config)
        }
    }

    fun startWithEncoded(tunFd: Int, encodedConfig: String): Result<Unit> {
        return runCatching {
            ensureLoaded()
            val err = nativeStart(tunFd, encodedConfig)
            if (err.isNotEmpty()) {
                error(err)
            }
        }
    }

    fun start(tunFd: Int, config: NativeEngineConfig): Result<Unit> {
        return runCatching {
            ensureLoaded()
            val err = nativeStart(tunFd, encodeConfig(config))
            if (err.isNotEmpty()) {
                error(err)
            }
        }
    }

    fun stop() {
        if (!loaded) return
        runCatching { nativeStop() }
    }

    fun snapshot(): TelemetrySnapshot {
        if (!loaded) return TelemetrySnapshot()
        return runCatching { decodeSnapshot(nativeSnapshotJson()) }
            .getOrDefault(TelemetrySnapshot())
    }

    fun runDoctor(config: NativeEngineConfig): DoctorReport {
        return runCatching {
            ensureLoaded()
            decodeDoctorReport(nativeRunDoctor(encodeConfig(config)))
        }.getOrElse { err ->
            DoctorReport(
                ok = false,
                checks = listOf(
                    DoctorCheck(
                        name = "Native Library",
                        target = "libvdpi_android.so",
                        passed = false,
                        latencyMs = 0L,
                        detail = err.message ?: "failed to load native engine",
                    )
                )
            )
        }
    }

    fun clearCache(): Boolean {
        if (!loaded) return true
        return runCatching {
            nativeClearCache()
            true
        }.getOrDefault(false)
    }

    fun version(): String {
        return runCatching {
            ensureLoaded()
            nativeVersion()
        }.getOrDefault(BuildConfig.VERSION_NAME)
    }
}
