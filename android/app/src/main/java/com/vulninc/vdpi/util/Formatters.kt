package com.vulninc.vdpi.util

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

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

fun formatStageShort(stageNumber: Int, stageLabel: String): String {
    val human = when (stageLabel) {
        "ComboMultiRecord" -> "Combo"
        "OobSniDesync" -> "OOB SNI"
        "MultiRecordOob" -> "Multi + OOB"
        "FineFragment" -> "Fine Fragment"
        "DeepRecordStorm" -> "Deep Storm"
        "SlowSniSlice" -> "Slow SNI"
        "DirectPassthrough" -> "Passthrough"
        else -> stageLabel
    }
    return "Stage $stageNumber · $human"
}

fun formatEventTime(tsMs: Long): String {
    if (tsMs <= 0L) return "--:--:--"
    val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)
    return fmt.format(Date(tsMs))
}

fun sanitizeDomainInput(raw: String): String {
    return raw
        .trim()
        .removePrefix("https://")
        .removePrefix("http://")
        .substringBefore('/')
        .substringBefore(':')
        .trim()
        .lowercase(Locale.US)
}
