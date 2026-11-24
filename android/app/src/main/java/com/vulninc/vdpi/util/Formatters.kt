package com.vulninc.vdpi.util

import java.net.URI
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

private val EVENT_TIME_FORMATTER: DateTimeFormatter =
    DateTimeFormatter.ofPattern("HH:mm:ss", Locale.US)

private val IPV4_REGEX = Regex(
    "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$"
)
private val IPV6_CHARS_REGEX = Regex("^[0-9a-fA-F:]+$")
private val DOMAIN_LABEL_REGEX = Regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

fun formatBytes(bytes: Long): String {
    if (bytes < 0L) return "0 B"
    if (bytes < 1024L) return "$bytes B"
    val kb = bytes / 1024.0
    if (kb < 1024.0) return String.format(Locale.US, "%.1f KB", kb)
    val mb = kb / 1024.0
    if (mb < 1024.0) return String.format(Locale.US, "%.1f MB", mb)
    val gb = mb / 1024.0
    return String.format(Locale.US, "%.2f GB", gb)
}

fun formatUptime(totalSecs: Long): String {
    val safe = totalSecs.coerceAtLeast(0L)
    val h = safe / 3600L
    val m = (safe % 3600L) / 60L
    val s = safe % 60L
    return String.format(Locale.US, "%02d:%02d:%02d", h, m, s)
}

fun formatStageLabel(stageLabel: String): String = when (stageLabel) {
    "ComboMultiRecord" -> "Combo"
    "OobSniDesync" -> "OOB SNI"
    "MultiRecordOob" -> "Multi + OOB"
    "FineFragment" -> "Fine Fragment"
    "DeepRecordStorm" -> "Deep Storm"
    "SlowSniSlice" -> "Slow SNI"
    "DirectPassthrough" -> "Passthrough"
    else -> stageLabel
}

fun formatStageShort(stageNumber: Int, stageLabel: String): String {
    return "Stage $stageNumber · ${formatStageLabel(stageLabel)}"
}

fun formatEventTime(tsMs: Long): String {
    if (tsMs <= 0L) return "--:--:--"
    return Instant.ofEpochMilli(tsMs)
        .atZone(ZoneId.systemDefault())
        .format(EVENT_TIME_FORMATTER)
}

fun sanitizeDomainInput(raw: String): String {
    return raw
        .trim()
        .lowercase(Locale.ROOT)
        .removePrefix("https://")
        .removePrefix("http://")
        .substringBefore('/')
        .substringBefore('?')
        .substringBefore('#')
        .substringBefore(':')
        .trim()
        .trimEnd('.')
}

fun isValidBypassDomain(raw: String): Boolean {
    val cleaned = sanitizeDomainInput(raw)
    if (cleaned.isEmpty() || cleaned.length > 253 || cleaned.any { it.isWhitespace() }) {
        return false
    }
    val host = cleaned.removePrefix("*.")
    val labels = host.split('.')
    if (labels.size < 2) return false
    return labels.all { DOMAIN_LABEL_REGEX.matches(it) }
}

fun isValidDnsInput(raw: String): Boolean {
    val trimmed = raw.trim()
    if (trimmed.isEmpty() || trimmed.any { it.isWhitespace() }) return false
    val lower = trimmed.lowercase(Locale.ROOT)
    if (lower.startsWith("https://")) {
        return runCatching {
            val uri = URI(trimmed)
            uri.scheme.equals("https", ignoreCase = true) &&
                !uri.host.isNullOrBlank() &&
                (uri.port == -1 || uri.port in 1..65535)
        }.getOrDefault(false)
    }
    if (IPV4_REGEX.matches(trimmed)) return true
    val hasLeadingBracket = trimmed.startsWith("[")
    val hasTrailingBracket = trimmed.endsWith("]")
    if (hasLeadingBracket != hasTrailingBracket) return false
    val unbracketed = if (hasLeadingBracket) {
        trimmed.substring(1, trimmed.length - 1)
    } else {
        trimmed
    }
    if (unbracketed.contains(':') && IPV6_CHARS_REGEX.matches(unbracketed)) {
        if (unbracketed.contains(":::")) return false
        val hasLeadingSingleColon = unbracketed.startsWith(":") && !unbracketed.startsWith("::")
        val hasTrailingSingleColon = unbracketed.endsWith(":") && !unbracketed.endsWith("::")
        if (hasLeadingSingleColon || hasTrailingSingleColon) return false
        val doubleColons = unbracketed.windowed(2).count { it == "::" }
        val groups = unbracketed.split(':').filter { it.isNotEmpty() }
        val validGroupCount = (doubleColons == 0 && groups.size == 8) ||
            (doubleColons == 1 && groups.size in 1..7)
        return validGroupCount && groups.all { it.length <= 4 }
    }
    return false
}
