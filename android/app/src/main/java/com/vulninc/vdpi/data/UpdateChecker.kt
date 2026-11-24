package com.vulninc.vdpi.data

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.Locale

@Serializable
data class ReleaseUpdateInfo(
    val latestVersion: String,
    val releaseUrl: String,
    val apkDownloadUrl: String?,
    val releaseNotes: String,
)

@Serializable
private data class GitHubReleaseAsset(
    val name: String = "",
    @SerialName("browser_download_url") val browserDownloadUrl: String = "",
)

@Serializable
private data class GitHubLatestRelease(
    @SerialName("tag_name") val tagName: String = "",
    @SerialName("html_url") val htmlUrl: String = "",
    val body: String? = null,
    val draft: Boolean = false,
    val prerelease: Boolean = false,
    val assets: List<GitHubReleaseAsset> = emptyList(),
)

object UpdateChecker {
    private const val LATEST_RELEASE_API_URL =
        "https://api.github.com/repos/Vuln-Inc/vdpi/releases/latest"
    private const val FALLBACK_RELEASE_PAGE_URL =
        "https://github.com/Vuln-Inc/vdpi/releases/latest"
    private const val CONNECT_TIMEOUT_MS = 8_000
    private const val READ_TIMEOUT_MS = 8_000
    private const val MAX_RESPONSE_BYTES = 512 * 1024

    private val STABLE_SEMVER_REGEX = Regex("^[vV]?(\\d+)\\.(\\d+)\\.(\\d+)$")

    private val json = Json {
        ignoreUnknownKeys = true
    }

    private data class SemVer(
        val major: Long,
        val minor: Long,
        val patch: Long,
    ) : Comparable<SemVer> {
        override fun compareTo(other: SemVer): Int {
            if (major != other.major) return major.compareTo(other.major)
            if (minor != other.minor) return minor.compareTo(other.minor)
            return patch.compareTo(other.patch)
        }
    }

    private fun parseStableSemVer(raw: String, allowDebugSuffix: Boolean): SemVer? {
        var normalized = raw.trim()
        if (allowDebugSuffix && normalized.endsWith("-debug", ignoreCase = true)) {
            normalized = normalized.dropLast("-debug".length)
        }
        val match = STABLE_SEMVER_REGEX.matchEntire(normalized) ?: return null
        val major = match.groupValues[1].toLongOrNull() ?: return null
        val minor = match.groupValues[2].toLongOrNull() ?: return null
        val patch = match.groupValues[3].toLongOrNull() ?: return null
        return SemVer(major, minor, patch)
    }

    internal fun normalizeVersionTag(raw: String): String =
        raw.trim().removePrefix("v").removePrefix("V")

    fun isNewerVersion(latest: String, current: String): Boolean {
        val latestVer = parseStableSemVer(latest, allowDebugSuffix = false) ?: return false
        val currentVer = parseStableSemVer(current, allowDebugSuffix = true) ?: return false
        return latestVer > currentVer
    }

    suspend fun checkLatestRelease(currentVersion: String): ReleaseUpdateInfo? =
        fetchLatestReleaseResult(currentVersion).getOrNull()

    internal suspend fun fetchLatestReleaseResult(
        currentVersion: String,
    ): Result<ReleaseUpdateInfo?> = withContext(Dispatchers.IO) {
        try {
            val connection = (URL(LATEST_RELEASE_API_URL).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
                instanceFollowRedirects = true
                useCaches = false
                setRequestProperty("Accept", "application/vnd.github+json")
                setRequestProperty("X-GitHub-Api-Version", "2022-11-28")
                setRequestProperty(
                    "User-Agent",
                    "vdpi-android/${normalizeVersionTag(currentVersion).ifEmpty { "0.0.0" }}",
                )
            }

            val cancelHandle = coroutineContext[Job]?.invokeOnCompletion { cause ->
                if (cause != null) {
                    runCatching { connection.disconnect() }
                }
            }
            try {
                coroutineContext.ensureActive()
                val statusCode = connection.responseCode
                if (statusCode !in 200..299) {
                    runCatching { connection.errorStream?.close() }
                    error("GitHub API returned HTTP $statusCode")
                }

                val bodyText = BufferedInputStream(connection.inputStream).use { input ->
                    val out = ByteArrayOutputStream()
                    val buf = ByteArray(4096)
                    var total = 0
                    while (true) {
                        coroutineContext.ensureActive()
                        val read = input.read(buf)
                        if (read <= 0) break
                        total += read
                        if (total > MAX_RESPONSE_BYTES) {
                            error("Release payload exceeded size limit")
                        }
                        out.write(buf, 0, read)
                    }
                    out.toString(Charsets.UTF_8.name())
                }

                val release = json.decodeFromString(GitHubLatestRelease.serializer(), bodyText)
                if (release.draft || release.prerelease) {
                    return@withContext Result.success(null)
                }
                if (!isNewerVersion(release.tagName, currentVersion)) {
                    return@withContext Result.success(null)
                }

                val latestVersion = normalizeVersionTag(release.tagName)
                val releaseUrl = release.htmlUrl.trim()
                    .takeIf { it.startsWith("https://", ignoreCase = true) }
                    ?: FALLBACK_RELEASE_PAGE_URL
                val apkUrl = release.assets.firstOrNull { asset ->
                    asset.name.trim().lowercase(Locale.ROOT).endsWith(".apk") &&
                        asset.browserDownloadUrl.trim().startsWith("https://", ignoreCase = true)
                }?.browserDownloadUrl?.trim()

                Result.success(
                    ReleaseUpdateInfo(
                        latestVersion = latestVersion,
                        releaseUrl = releaseUrl,
                        apkDownloadUrl = apkUrl,
                        releaseNotes = release.body?.trim().orEmpty(),
                    )
                )
            } finally {
                cancelHandle?.dispose()
                runCatching { connection.disconnect() }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (t: Throwable) {
            coroutineContext.ensureActive()
            Result.failure(t)
        }
    }
}
