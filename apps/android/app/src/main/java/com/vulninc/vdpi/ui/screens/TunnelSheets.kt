package com.vulninc.vdpi.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.DialogWindowProvider
import androidx.core.view.WindowCompat
import com.vulninc.vdpi.engine.DoctorCheck
import com.vulninc.vdpi.engine.DoctorReport
import com.vulninc.vdpi.engine.EngineEvent
import com.vulninc.vdpi.ui.DoctorUiState
import com.vulninc.vdpi.ui.components.HairlineRule
import com.vulninc.vdpi.ui.components.InsetGroupedCard
import com.vulninc.vdpi.ui.components.SectionFooter
import com.vulninc.vdpi.ui.components.SectionOverline
import com.vulninc.vdpi.ui.theme.GeistMono
import com.vulninc.vdpi.ui.theme.GeistSans
import com.vulninc.vdpi.ui.theme.VdpiTextStyles
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens
import com.vulninc.vdpi.util.formatEventTime
import kotlinx.coroutines.delay
import java.util.Locale

private val DarkLogWellBackground = Color(0xFF0D0D0F)

// ── System Bar Sync ──

@Composable
internal fun SyncModalSheetSystemBars(isDark: Boolean) {
    val view = LocalView.current
    SideEffect {
        val window = (view.parent as? DialogWindowProvider)?.window ?: return@SideEffect
        WindowCompat.getInsetsController(window, view).apply {
            isAppearanceLightNavigationBars = !isDark
            isAppearanceLightStatusBars = !isDark
        }
        @Suppress("DEPRECATION")
        window.navigationBarColor = android.graphics.Color.TRANSPARENT
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            window.isNavigationBarContrastEnforced = false
        }
    }
}

// ── Shared Sheet Chrome ──

@Composable
internal fun SheetGrabber(compact: Boolean = false) {
    val palette = VdpiThemeTokens.palette
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(
                top = if (compact) 6.dp else 10.dp,
                bottom = if (compact) 4.dp else 6.dp,
            ),
        contentAlignment = Alignment.Center,
    ) {
        Box(
            modifier = Modifier
                .size(width = 36.dp, height = 5.dp)
                .clip(CircleShape)
                .background(palette.inkMuted.copy(alpha = 0.45f)),
        )
    }
}

@Composable
internal fun SheetTextButton(
    label: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    emphasized: Boolean = false,
    enabled: Boolean = true,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val interaction = remember { MutableInteractionSource() }

    Box(
        modifier = modifier
            .widthIn(min = 44.dp)
            .heightIn(min = 44.dp)
            .alpha(if (enabled) 1f else 0.4f)
            .clickable(
                interactionSource = interaction,
                indication = null,
                enabled = enabled,
                role = Role.Button,
            ) {
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                onClick()
            }
            .padding(horizontal = 4.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = label,
            fontFamily = GeistSans,
            fontWeight = if (emphasized) FontWeight.SemiBold else FontWeight.Normal,
            fontSize = 16.sp,
            color = palette.accent,
            maxLines = 1,
        )
    }
}

@Composable
private fun SheetHeaderBar(
    title: String,
    leadingLabel: String,
    leadingEnabled: Boolean,
    onLeadingClick: () -> Unit,
    onDismiss: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 44.dp),
    ) {
        SheetTextButton(
            label = leadingLabel,
            enabled = leadingEnabled,
            onClick = onLeadingClick,
            modifier = Modifier.align(Alignment.CenterStart),
        )
        Text(
            text = title,
            style = VdpiTextStyles.sheetTitle,
            color = palette.inkPrimary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.align(Alignment.Center),
        )
        SheetTextButton(
            label = "Done",
            emphasized = true,
            onClick = onDismiss,
            modifier = Modifier.align(Alignment.CenterEnd),
        )
    }
}

// ── Diagnostics Sheet ──

@Composable
internal fun DoctorSheetContent(
    doctorState: DoctorUiState,
    isLandscape: Boolean,
    onRerun: () -> Unit,
    onDismiss: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val cardBackground = if (palette.isDark) palette.surfaceRaised else palette.surface
    val report = doctorState.report

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .then(
                if (isLandscape) {
                    Modifier.windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal))
                } else {
                    Modifier
                },
            )
            .verticalScroll(rememberScrollState()),
        contentAlignment = Alignment.TopCenter,
    ) {
        Column(
            modifier = Modifier
                .then(if (isLandscape) Modifier.widthIn(max = 580.dp) else Modifier)
                .fillMaxWidth()
                .then(
                    if (isLandscape) {
                        Modifier.windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Bottom))
                    } else {
                        Modifier.navigationBarsPadding()
                    },
                )
                .padding(horizontal = 16.dp)
                .padding(bottom = if (isLandscape) 14.dp else 24.dp),
        ) {
            SheetHeaderBar(
                title = "Diagnostics",
                leadingLabel = "Re-run",
                leadingEnabled = !doctorState.running,
                onLeadingClick = onRerun,
                onDismiss = onDismiss,
            )

            Spacer(Modifier.height(if (isLandscape) 8.dp else 14.dp))

            SectionOverline(text = "Checks")

            InsetGroupedCard(
                modifier = Modifier.fillMaxWidth(),
                radius = 16.dp,
                backgroundColor = cardBackground,
            ) {
                when {
                    doctorState.running -> {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(min = if (isLandscape) 46.dp else 54.dp)
                                .padding(
                                    horizontal = 16.dp,
                                    vertical = if (isLandscape) 10.dp else 14.dp,
                                ),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(18.dp),
                                strokeWidth = 2.dp,
                                color = palette.inkSecondary,
                            )
                            Spacer(Modifier.width(12.dp))
                            Text(
                                text = "Verifying DNS, DoH, and TLS connectivity...",
                                style = VdpiTextStyles.body,
                                color = palette.inkSecondary,
                            )
                        }
                    }

                    report != null && report.checks.isNotEmpty() -> {
                        report.checks.forEachIndexed { idx, check ->
                            if (idx > 0) {
                                HairlineRule(startIndent = 48.dp)
                            }
                            DoctorCheckRow(
                                check = check,
                                isLandscape = isLandscape,
                            )
                        }
                    }

                    report != null -> {
                        DoctorMessageBox(
                            message = "No diagnostic checks were returned. Tap Re-run to try again.",
                            isLandscape = isLandscape,
                        )
                    }

                    else -> {
                        DoctorMessageBox(
                            message = "Tap Re-run to verify DNS, DoH, and TLS endpoints.",
                            isLandscape = isLandscape,
                        )
                    }
                }
            }

            if (!doctorState.running && report != null && report.checks.isNotEmpty()) {
                SectionFooter(text = formatDoctorFooter(report))
            }
        }
    }
}

@Composable
private fun DoctorCheckRow(
    check: DoctorCheck,
    isLandscape: Boolean,
) {
    val palette = VdpiThemeTokens.palette
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = if (isLandscape) 44.dp else 50.dp)
            .semantics(mergeDescendants = true) {
                contentDescription =
                    "${check.name}, ${if (check.passed) "Passed" else "Failed"}, ${check.latencyMs} ms, ${check.detail}"
            }
            .padding(
                horizontal = 16.dp,
                vertical = if (isLandscape) 9.dp else 12.dp,
            ),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (check.passed) {
            CheckCircleGlyph(tint = palette.signal)
        } else {
            CrossCircleGlyph(tint = palette.danger)
        }

        Spacer(Modifier.width(12.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = check.name,
                style = VdpiTextStyles.rowTitle,
                color = palette.inkPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (check.detail.isNotBlank()) {
                Spacer(Modifier.height(2.dp))
                Text(
                    text = check.detail,
                    style = VdpiTextStyles.caption,
                    color = palette.inkSecondary,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }

        Spacer(Modifier.width(12.dp))

        Text(
            text = "${check.latencyMs} ms",
            style = VdpiTextStyles.caption.copy(fontFeatureSettings = "tnum"),
            color = palette.inkSecondary,
            maxLines = 1,
        )
    }
}

@Composable
private fun DoctorMessageBox(
    message: String,
    isLandscape: Boolean,
) {
    val palette = VdpiThemeTokens.palette
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(
                horizontal = 16.dp,
                vertical = if (isLandscape) 14.dp else 20.dp,
            ),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = message,
            style = VdpiTextStyles.body,
            color = palette.inkSecondary,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun CheckCircleGlyph(tint: Color) {
    val checkColor = if (VdpiThemeTokens.palette.isDark) Color(0xFF000000) else Color.White
    Canvas(modifier = Modifier.size(20.dp)) {
        val w = size.width
        val h = size.height
        drawCircle(color = tint, radius = size.minDimension * 0.46f)
        val check = Path().apply {
            moveTo(w * 0.30f, h * 0.52f)
            lineTo(w * 0.44f, h * 0.66f)
            lineTo(w * 0.71f, h * 0.36f)
        }
        drawPath(
            path = check,
            color = checkColor,
            style = Stroke(width = 1.9.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round),
        )
    }
}

@Composable
private fun CrossCircleGlyph(tint: Color) {
    Canvas(modifier = Modifier.size(20.dp)) {
        val w = size.width
        val h = size.height
        val strokePx = 1.9.dp.toPx()
        drawCircle(color = tint, radius = size.minDimension * 0.46f)
        drawLine(
            color = Color.White,
            start = Offset(w * 0.34f, h * 0.34f),
            end = Offset(w * 0.66f, h * 0.66f),
            strokeWidth = strokePx,
            cap = StrokeCap.Round,
        )
        drawLine(
            color = Color.White,
            start = Offset(w * 0.66f, h * 0.34f),
            end = Offset(w * 0.34f, h * 0.66f),
            strokeWidth = strokePx,
            cap = StrokeCap.Round,
        )
    }
}

private fun formatDoctorFooter(report: DoctorReport): String {
    val failedCount = report.checks.count { !it.passed }
    return if (report.ok && failedCount == 0) {
        "All ${report.checks.size} checks passed"
    } else {
        val noun = if (failedCount == 1) "issue" else "issues"
        "$failedCount $noun detected - check DNS or network settings"
    }
}

// ── Engine Logs Sheet ──

@Composable
internal fun EngineLogSheetContent(
    events: List<EngineEvent>,
    isLandscape: Boolean,
    onDismiss: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val context = LocalContext.current
    val listState = rememberLazyListState()
    var copiedFeedback by remember { mutableStateOf(false) }
    var copyTick by remember { mutableIntStateOf(0) }

    LaunchedEffect(copyTick) {
        if (copyTick > 0) {
            delay(1800L)
            copiedFeedback = false
        }
    }

    LaunchedEffect(events.size) {
        if (events.isNotEmpty()) {
            val lastVisible = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index
            val nearBottom = lastVisible == null || lastVisible >= (events.size - 3).coerceAtLeast(0)
            if (nearBottom) {
                listState.scrollToItem(events.lastIndex)
            }
        }
    }

    val logWellBackground = if (palette.isDark) DarkLogWellBackground else palette.surface

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .then(
                if (isLandscape) {
                    Modifier.windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal))
                } else {
                    Modifier
                },
            ),
        contentAlignment = Alignment.TopCenter,
    ) {
        Column(
            modifier = Modifier
                .then(if (isLandscape) Modifier.widthIn(max = 580.dp) else Modifier)
                .fillMaxWidth()
                .then(
                    if (isLandscape) {
                        Modifier.windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Bottom))
                    } else {
                        Modifier.navigationBarsPadding()
                    },
                )
                .padding(horizontal = 16.dp)
                .padding(bottom = if (isLandscape) 14.dp else 24.dp),
        ) {
            SheetHeaderBar(
                title = "Engine Logs",
                leadingLabel = if (copiedFeedback) "Copied" else "Copy",
                leadingEnabled = events.isNotEmpty(),
                onLeadingClick = {
                    copyEngineLogsToClipboard(context, events)
                    copiedFeedback = true
                    copyTick++
                },
                onDismiss = onDismiss,
            )

            Spacer(Modifier.height(if (isLandscape) 8.dp else 12.dp))

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f, fill = false)
                    .heightIn(
                        min = if (isLandscape) 100.dp else 140.dp,
                        max = if (isLandscape) 220.dp else 380.dp,
                    )
                    .clip(RoundedCornerShape(14.dp))
                    .background(logWellBackground)
                    .padding(if (isLandscape) 10.dp else 12.dp),
            ) {
                if (events.isEmpty()) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .align(Alignment.Center)
                            .verticalScroll(rememberScrollState())
                            .padding(
                                vertical = if (isLandscape) 14.dp else 24.dp,
                                horizontal = 16.dp,
                            ),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Text(
                            text = "No Engine Logs Yet",
                            style = VdpiTextStyles.rowTitle.copy(fontWeight = FontWeight.Medium),
                            color = palette.inkPrimary,
                            textAlign = TextAlign.Center,
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = "Connect the tunnel to record activity.",
                            style = VdpiTextStyles.caption,
                            color = palette.inkSecondary,
                            textAlign = TextAlign.Center,
                        )
                    }
                } else {
                    LazyColumn(
                        state = listState,
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        itemsIndexed(
                            items = events,
                            key = { idx, ev -> if (ev.seq > 0L) ev.seq else "${ev.tsMs}-${ev.tag}-$idx" },
                        ) { _, ev ->
                            EngineEventRow(event = ev)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun EngineEventRow(event: EngineEvent) {
    val palette = VdpiThemeTokens.palette
    val levelTag = formatLogLevelTag(event.level)
    val levelColor = when (event.level.lowercase(Locale.ROOT)) {
        "error", "err" -> palette.danger
        "warn", "warning" -> palette.warning
        else -> palette.inkSecondary
    }
    val line = remember(event, levelColor, palette.inkMuted, palette.inkPrimary) {
        buildAnnotatedString {
            withStyle(SpanStyle(color = palette.inkMuted)) {
                append(formatEventTime(event.tsMs))
                append(' ')
            }
            withStyle(SpanStyle(color = levelColor, fontWeight = FontWeight.Medium)) {
                append(levelTag)
                append(' ')
            }
            withStyle(SpanStyle(color = palette.inkPrimary)) {
                append('[')
                append(event.tag)
                append("] ")
                append(event.message)
            }
        }
    }
    Text(
        text = line,
        style = VdpiTextStyles.monoSmall.copy(
            fontFamily = GeistMono,
            fontSize = 12.sp,
            lineHeight = 18.sp,
            fontFeatureSettings = "tnum",
        ),
    )
}

internal fun isAlertLogLevel(level: String): Boolean =
    level.equals("error", ignoreCase = true) ||
        level.equals("err", ignoreCase = true) ||
        level.equals("warn", ignoreCase = true) ||
        level.equals("warning", ignoreCase = true)

private fun formatLogLevelTag(level: String): String = when (level.lowercase(Locale.ROOT)) {
    "error", "err" -> "[ERR]"
    "warn", "warning" -> "[WARN]"
    else -> "[INFO]"
}

private fun formatEngineLogDump(events: List<EngineEvent>): String =
    events.joinToString("\n") { ev ->
        val level = formatLogLevelTag(ev.level)
        "${formatEventTime(ev.tsMs)} $level [${ev.tag}] ${ev.message}"
    }

private fun copyEngineLogsToClipboard(context: Context, events: List<EngineEvent>) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    cm?.setPrimaryClip(ClipData.newPlainText("vdpi engine logs", formatEngineLogDump(events)))
}
