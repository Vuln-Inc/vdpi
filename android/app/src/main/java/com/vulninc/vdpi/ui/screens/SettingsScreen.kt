package com.vulninc.vdpi.ui.screens

import android.content.Intent
import android.content.res.Configuration
import android.net.Uri
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.SizeTransform
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vulninc.vdpi.data.ThemePreference
import com.vulninc.vdpi.data.VdpiSettings
import com.vulninc.vdpi.engine.DesyncMode
import com.vulninc.vdpi.ui.components.HairlineRule
import com.vulninc.vdpi.ui.components.InsetGroupedCard
import com.vulninc.vdpi.ui.components.InsetGroupedRow
import com.vulninc.vdpi.ui.components.LocalBottomChromePadding
import com.vulninc.vdpi.ui.components.LocalReduceMotion
import com.vulninc.vdpi.ui.components.LocalTopOverlayPadding
import com.vulninc.vdpi.ui.components.PrecisionSwitch
import com.vulninc.vdpi.ui.components.SectionFooter
import com.vulninc.vdpi.ui.components.SectionOverline
import com.vulninc.vdpi.ui.components.SegmentedControl
import com.vulninc.vdpi.ui.components.sculptedDarkCardBorder
import com.vulninc.vdpi.ui.theme.GeistSans
import com.vulninc.vdpi.ui.theme.VdpiTextStyles
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens
import com.vulninc.vdpi.util.isValidBypassDomain
import com.vulninc.vdpi.util.isValidDnsInput
import com.vulninc.vdpi.util.sanitizeDomainInput

private data class DnsPreset(
    val name: String,
    val address: String,
)

private val DNS_PRESETS = listOf(
    DnsPreset(name = "Cloudflare", address = "1.1.1.1"),
    DnsPreset(name = "Google", address = "8.8.8.8"),
    DnsPreset(name = "AdGuard", address = "94.140.14.140"),
    DnsPreset(name = "Quad9", address = "9.9.9.9"),
)

private const val GITHUB_REPO_URL = "https://github.com/Vuln-Inc/vdpi"
private const val GITHUB_REPO_LABEL = "github.com/Vuln-Inc/vdpi"

// ── Screen ──

@Composable
fun SettingsScreen(
    settings: VdpiSettings,
    engineVersion: String,
    onSetDesyncMode: (DesyncMode) -> Unit,
    onSetChunkSize: (Int) -> Unit,
    onSetDnsAddr: (String) -> Unit,
    onSetEnableDoh: (Boolean) -> Unit,
    onSetIpv4Only: (Boolean) -> Unit,
    onSetBlockQuic: (Boolean) -> Unit,
    onAddBypassDomain: (String) -> Unit,
    onRemoveBypassDomain: (String) -> Unit,
    onSetTheme: (ThemePreference) -> Unit,
    onOpenAlwaysOnVpn: () -> Unit,
    onClearCache: () -> Unit,
    modifier: Modifier = Modifier,
    availableUpdate: UpdateBannerInfo? = null,
    isCheckingUpdate: Boolean = false,
    updateStatusMessage: String? = null,
    onCheckForUpdates: () -> Unit = {},
    onExportSettings: () -> Unit = {},
    onImportSettings: () -> Unit = {},
) {
    val context = LocalContext.current
    val configuration = LocalConfiguration.current
    val isLandscape = configuration.orientation == Configuration.ORIENTATION_LANDSCAPE &&
        configuration.screenWidthDp >= 560
    val haptic = LocalHapticFeedback.current
    val bottomChromePadding = LocalBottomChromePadding.current
    val topOverlayPadding = LocalTopOverlayPadding.current
    val sectionGap = if (isLandscape) 20.dp else 24.dp

    fun openExternalUrl(url: String) {
        if (url.isBlank()) return
        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
        runCatching {
            context.startActivity(
                Intent(Intent.ACTION_VIEW, Uri.parse(url)),
            )
        }
    }

    fun openGitHubRepository() {
        openExternalUrl(GITHUB_REPO_URL)
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal))
            .padding(horizontal = if (isLandscape) 24.dp else 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(
            modifier = if (isLandscape) {
                Modifier
                    .widthIn(max = 720.dp)
                    .fillMaxWidth()
            } else {
                Modifier.fillMaxWidth()
            },
        ) {
            Spacer(Modifier.height(topOverlayPadding + if (isLandscape) 6.dp else 12.dp))
            SettingsHeader(isLandscape = isLandscape)
            Spacer(Modifier.height(if (isLandscape) 14.dp else 24.dp))

            DesyncSettingsSection(
                desyncMode = settings.desyncMode,
                chunkSize = settings.chunkSize,
                onSetDesyncMode = onSetDesyncMode,
                onSetChunkSize = onSetChunkSize,
            )
            Spacer(Modifier.height(sectionGap))

            DnsSettingsSection(
                dnsAddr = settings.dnsAddr,
                enableDoh = settings.enableDoh,
                blockQuic = settings.blockQuic,
                ipv4Only = settings.ipv4Only,
                onSetDnsAddr = onSetDnsAddr,
                onSetEnableDoh = onSetEnableDoh,
                onSetBlockQuic = onSetBlockQuic,
                onSetIpv4Only = onSetIpv4Only,
            )
            Spacer(Modifier.height(sectionGap))

            BypassDomainsSection(
                bypassDomains = settings.bypassDomains,
                onAddBypassDomain = onAddBypassDomain,
                onRemoveBypassDomain = onRemoveBypassDomain,
            )
            Spacer(Modifier.height(sectionGap))

            AppearanceSettingsSection(
                theme = settings.theme,
                onSetTheme = onSetTheme,
            )
            Spacer(Modifier.height(sectionGap))

            SystemSettingsSection(
                onClearCache = onClearCache,
                onOpenAlwaysOnVpn = onOpenAlwaysOnVpn,
            )
            Spacer(Modifier.height(sectionGap))

            BackupRestoreSection(
                onExportSettings = onExportSettings,
                onImportSettings = onImportSettings,
            )
            Spacer(Modifier.height(sectionGap))

            UpdatesSettingsSection(
                appVersion = engineVersion,
                availableUpdate = availableUpdate,
                isCheckingUpdate = isCheckingUpdate,
                updateStatusMessage = updateStatusMessage,
                onCheckForUpdates = onCheckForUpdates,
                onOpenReleaseUrl = ::openExternalUrl,
            )
            Spacer(Modifier.height(sectionGap))

            AboutSettingsSection(onOpenGitHub = ::openGitHubRepository)
            Spacer(Modifier.height(if (isLandscape) 10.dp else 12.dp))

            VersionAttributionFooter(
                engineVersion = engineVersion,
                onOpenGitHub = ::openGitHubRepository,
            )
            Spacer(Modifier.height(bottomChromePadding + 8.dp))
        }
    }
}

@Composable
private fun SettingsHeader(isLandscape: Boolean) {
    val palette = VdpiThemeTokens.palette
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = if (isLandscape) 34.dp else 44.dp),
        contentAlignment = Alignment.CenterStart,
    ) {
        Text(
            text = "Settings",
            style = if (isLandscape) {
                VdpiTextStyles.pageTitle.copy(
                    fontSize = 24.sp,
                    lineHeight = 30.sp,
                    letterSpacing = (-0.3).sp,
                )
            } else {
                VdpiTextStyles.pageTitle
            },
            color = palette.inkPrimary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

// ── Sections ──

@Composable
private fun DesyncSettingsSection(
    desyncMode: DesyncMode,
    chunkSize: Int,
    onSetDesyncMode: (DesyncMode) -> Unit,
    onSetChunkSize: (Int) -> Unit,
) {
    val haptic = LocalHapticFeedback.current

    Column(modifier = Modifier.fillMaxWidth()) {
        SectionOverline("Desync Engine")
        InsetGroupedCard(
            modifier = Modifier
                .fillMaxWidth()
                .sculptedDarkCardBorder(16.dp),
            radius = 16.dp,
        ) {
            DesyncMode.entries.forEachIndexed { idx, mode ->
                if (idx > 0) HairlineRule(startIndent = 16.dp)
                val isSelected = desyncMode == mode
                InsetGroupedRow(
                    title = mode.label,
                    subtitle = mode.summary,
                    modifier = Modifier.semantics { selected = isSelected },
                    onClick = {
                        if (!isSelected) {
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            onSetDesyncMode(mode)
                        }
                    },
                    trailing = {
                        SelectionCheckmark(visible = isSelected)
                    },
                )
            }

            HairlineRule(startIndent = 16.dp)

            ChunkSizeRow(
                chunkSize = chunkSize,
                onDecrease = {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onSetChunkSize((chunkSize - 1).coerceAtLeast(1))
                },
                onIncrease = {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onSetChunkSize((chunkSize + 1).coerceAtMost(64))
                },
            )
        }
        SectionFooter("Splits initial TLS ClientHello packets to evade DPI inspection. Chunk size sets the first fragment length (1–64 bytes).")
    }
}

@Composable
private fun DnsSettingsSection(
    dnsAddr: String,
    enableDoh: Boolean,
    blockQuic: Boolean,
    ipv4Only: Boolean,
    onSetDnsAddr: (String) -> Unit,
    onSetEnableDoh: (Boolean) -> Unit,
    onSetBlockQuic: (Boolean) -> Unit,
    onSetIpv4Only: (Boolean) -> Unit,
) {
    val haptic = LocalHapticFeedback.current
    val focusManager = LocalFocusManager.current

    val isPresetDns = DNS_PRESETS.any { it.address.equals(dnsAddr, ignoreCase = true) }
    var customDnsInput by remember(dnsAddr) {
        mutableStateOf(if (isPresetDns) "" else dnsAddr)
    }
    var dnsError by remember(dnsAddr) { mutableStateOf<String?>(null) }

    val dnsTrimmed = customDnsInput.trim()
    val dnsDirty = dnsTrimmed.isNotEmpty() && !dnsTrimmed.equals(dnsAddr, ignoreCase = true)
    val customDnsActive = !isPresetDns && !dnsDirty && dnsTrimmed.equals(dnsAddr, ignoreCase = true)

    fun submitDns() {
        val candidate = customDnsInput.trim()
        if (!isValidDnsInput(candidate)) {
            dnsError = "Enter a valid IPv4, IPv6, or https:// DoH URL"
            return
        }
        dnsError = null
        focusManager.clearFocus()
        if (!candidate.equals(dnsAddr, ignoreCase = true)) {
            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
            onSetDnsAddr(candidate)
        }
    }

    Column(modifier = Modifier.fillMaxWidth()) {
        SectionOverline("DNS & Privacy")
        InsetGroupedCard(
            modifier = Modifier
                .fillMaxWidth()
                .sculptedDarkCardBorder(16.dp),
            radius = 16.dp,
        ) {
            DNS_PRESETS.forEachIndexed { idx, preset ->
                if (idx > 0) HairlineRule(startIndent = 16.dp)
                val isSelected = dnsAddr.equals(preset.address, ignoreCase = true)
                InsetGroupedRow(
                    title = preset.name,
                    subtitle = preset.address,
                    subtitleTextDirection = TextDirection.Ltr,
                    modifier = Modifier.semantics { selected = isSelected },
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        customDnsInput = ""
                        dnsError = null
                        focusManager.clearFocus()
                        if (!isSelected) onSetDnsAddr(preset.address)
                    },
                    trailing = {
                        SelectionCheckmark(visible = isSelected)
                    },
                )
            }

            HairlineRule(startIndent = 16.dp)

            BorderlessInputRow(
                value = customDnsInput,
                placeholder = "Custom DNS (IP or https://...)",
                actionLabel = "Apply",
                actionEnabled = dnsDirty,
                showCheckmark = customDnsActive,
                errorText = dnsError,
                onValueChange = { next ->
                    customDnsInput = next
                    val trimmed = next.trim()
                    dnsError = when {
                        trimmed.isEmpty() -> null
                        dnsError != null && !isValidDnsInput(trimmed) -> dnsError
                        else -> null
                    }
                },
                onSubmit = ::submitDns,
            )

            HairlineRule(startIndent = 16.dp)

            ToggleSettingRow(
                title = "DNS over HTTPS",
                subtitle = "Encrypt DNS queries with automatic failover",
                checked = enableDoh,
                onCheckedChange = onSetEnableDoh,
            )

            HairlineRule(startIndent = 16.dp)

            ToggleSettingRow(
                title = "Block QUIC",
                subtitle = "Drop UDP/443 so apps fall back to TCP TLS",
                checked = blockQuic,
                onCheckedChange = onSetBlockQuic,
            )

            HairlineRule(startIndent = 16.dp)

            ToggleSettingRow(
                title = "IPv4 Only",
                subtitle = "Skip AAAA lookups and IPv6 tunnel routes",
                checked = ipv4Only,
                onCheckedChange = onSetIpv4Only,
            )
        }
        SectionFooter("Blocking QUIC forces HTTP/3 traffic onto TCP where DPI desync applies.")
    }
}

@Composable
private fun BypassDomainsSection(
    bypassDomains: List<String>,
    onAddBypassDomain: (String) -> Unit,
    onRemoveBypassDomain: (String) -> Unit,
) {
    val haptic = LocalHapticFeedback.current
    val focusManager = LocalFocusManager.current

    var bypassInput by remember { mutableStateOf("") }
    var bypassError by remember { mutableStateOf<String?>(null) }

    fun submitBypass() {
        val cleaned = sanitizeDomainInput(bypassInput)
        if (!isValidBypassDomain(cleaned)) {
            bypassError = "Enter a valid domain (e.g. example.com or *.example.com)"
            return
        }
        if (cleaned in bypassDomains) {
            bypassError = "$cleaned is already in the bypass list"
            return
        }
        bypassError = null
        bypassInput = ""
        focusManager.clearFocus()
        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
        onAddBypassDomain(cleaned)
    }

    Column(modifier = Modifier.fillMaxWidth()) {
        SectionOverline("Bypass Domains")
        InsetGroupedCard(
            modifier = Modifier
                .fillMaxWidth()
                .sculptedDarkCardBorder(16.dp),
            radius = 16.dp,
        ) {
            BorderlessInputRow(
                value = bypassInput,
                placeholder = "Add domain (e.g. example.com)",
                actionLabel = "Add",
                actionEnabled = bypassInput.isNotBlank(),
                showCheckmark = false,
                errorText = bypassError,
                onValueChange = { next ->
                    bypassInput = next
                    if (bypassError != null) bypassError = null
                },
                onSubmit = ::submitBypass,
            )

            bypassDomains.forEach { domain ->
                HairlineRule(startIndent = 16.dp)
                InsetGroupedRow(
                    title = domain,
                    titleTextDirection = TextDirection.Ltr,
                    trailing = {
                        RemoveDomainButton(
                            domain = domain,
                            onRemove = {
                                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                focusManager.clearFocus()
                                onRemoveBypassDomain(domain)
                            },
                        )
                    },
                )
            }
        }
        SectionFooter("Matching domains and subdomains connect directly without DPI desync. Local networks are bypassed automatically.")
    }
}

@Composable
private fun AppearanceSettingsSection(
    theme: ThemePreference,
    onSetTheme: (ThemePreference) -> Unit,
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        SectionOverline("Appearance")
        SegmentedControl(
            options = ThemePreference.entries,
            selected = theme,
            labelFor = { it.label },
            onSelect = onSetTheme,
        )
    }
}

@Composable
private fun SystemSettingsSection(
    onClearCache: () -> Unit,
    onOpenAlwaysOnVpn: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current

    Column(modifier = Modifier.fillMaxWidth()) {
        SectionOverline("System")
        InsetGroupedCard(
            modifier = Modifier
                .fillMaxWidth()
                .sculptedDarkCardBorder(16.dp),
            radius = 16.dp,
        ) {
            InsetGroupedRow(
                title = "Clear Engine Cache",
                subtitle = "Reset learned TLS stages and DNS entries",
                onClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onClearCache()
                },
            )

            HairlineRule(startIndent = 16.dp)

            InsetGroupedRow(
                title = "System VPN Settings",
                subtitle = "Configure Always-on VPN in Android settings",
                onClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onOpenAlwaysOnVpn()
                },
                trailing = {
                    ChevronRightGlyph(tint = palette.inkMuted)
                },
            )
        }
    }
}

@Composable
private fun BackupRestoreSection(
    onExportSettings: () -> Unit,
    onImportSettings: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current

    Column(modifier = Modifier.fillMaxWidth()) {
        SectionOverline("Backup & Restore")
        InsetGroupedCard(
            modifier = Modifier
                .fillMaxWidth()
                .sculptedDarkCardBorder(16.dp),
            radius = 16.dp,
        ) {
            InsetGroupedRow(
                title = "Export Settings",
                subtitle = "Save configuration as JSON",
                onClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onExportSettings()
                },
                trailing = {
                    ChevronRightGlyph(tint = palette.inkMuted)
                },
            )

            HairlineRule(startIndent = 16.dp)

            InsetGroupedRow(
                title = "Import Settings",
                subtitle = "Restore configuration from JSON",
                onClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onImportSettings()
                },
                trailing = {
                    ChevronRightGlyph(tint = palette.inkMuted)
                },
            )
        }
        SectionFooter("Exports desync, DNS, bypass domains, split tunnel, and theme preferences.")
    }
}

@Composable
private fun UpdatesSettingsSection(
    appVersion: String,
    availableUpdate: UpdateBannerInfo?,
    isCheckingUpdate: Boolean,
    updateStatusMessage: String?,
    onCheckForUpdates: () -> Unit,
    onOpenReleaseUrl: (String) -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val currentVersionTag = formatVersionTag(appVersion)

    Column(modifier = Modifier.fillMaxWidth()) {
        SectionOverline("Updates")
        InsetGroupedCard(
            modifier = Modifier
                .fillMaxWidth()
                .sculptedDarkCardBorder(16.dp),
            radius = 16.dp,
        ) {
            if (availableUpdate != null) {
                val latestTag = formatVersionTag(availableUpdate.latestVersion)
                InsetGroupedRow(
                    title = "Update Available · $latestTag",
                    subtitle = "Open release on GitHub",
                    modifier = Modifier.heightIn(min = 52.dp),
                    onClick = { onOpenReleaseUrl(availableUpdate.releaseUrl) },
                    leading = {
                        Box(
                            modifier = Modifier
                                .size(6.dp)
                                .clip(CircleShape)
                                .background(palette.accent),
                        )
                    },
                    trailing = {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(5.dp),
                        ) {
                            Text(
                                text = "Download",
                                fontFamily = GeistSans,
                                fontWeight = FontWeight.Medium,
                                fontSize = 14.sp,
                                color = palette.accent,
                                maxLines = 1,
                            )
                            ArrowUpRightGlyph(tint = palette.accent)
                        }
                    },
                )
            } else {
                val statusText = updateStatusMessage?.trim()?.takeIf { it.isNotEmpty() }
                val shortStatus = statusText?.takeIf { it.length <= 18 }
                val subtitleText = if (!isCheckingUpdate && shortStatus == null) statusText else null
                val trailingText = shortStatus ?: currentVersionTag

                InsetGroupedRow(
                    title = "Check for Updates",
                    subtitle = subtitleText,
                    modifier = Modifier.heightIn(min = 52.dp),
                    onClick = if (isCheckingUpdate) {
                        null
                    } else {
                        {
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            onCheckForUpdates()
                        }
                    },
                    trailing = {
                        if (isCheckingUpdate) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                strokeWidth = 1.8.dp,
                                color = palette.inkSecondary,
                            )
                        } else {
                            Text(
                                text = trailingText,
                                style = VdpiTextStyles.monoMetric.copy(fontSize = 14.sp),
                                color = palette.inkSecondary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    },
                )
            }
        }
    }
}

@Composable
private fun AboutSettingsSection(
    onOpenGitHub: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette

    Column(modifier = Modifier.fillMaxWidth()) {
        SectionOverline("About")
        InsetGroupedCard(
            modifier = Modifier
                .fillMaxWidth()
                .sculptedDarkCardBorder(16.dp),
            radius = 16.dp,
        ) {
            InsetGroupedRow(
                title = "GitHub Repository",
                subtitle = GITHUB_REPO_LABEL,
                subtitleTextDirection = TextDirection.Ltr,
                modifier = Modifier.heightIn(min = 52.dp),
                onClick = onOpenGitHub,
                trailing = {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(5.dp),
                    ) {
                        Text(
                            text = "Open",
                            fontFamily = GeistSans,
                            fontWeight = FontWeight.Medium,
                            fontSize = 14.sp,
                            color = palette.accent,
                            maxLines = 1,
                        )
                        ArrowUpRightGlyph(tint = palette.accent)
                    }
                },
            )
        }
    }
}

@Composable
private fun VersionAttributionFooter(
    engineVersion: String,
    onOpenGitHub: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val versionLabel = formatVersionTag(engineVersion)
    val footerInteraction = remember { MutableInteractionSource() }
    val footerPressed by footerInteraction.collectIsPressedAsState()
    val footerColor by animateColorAsState(
        targetValue = if (footerPressed) palette.accent else palette.inkMuted,
        animationSpec = tween(durationMillis = if (footerPressed) 60 else 160),
        label = "versionFooterColor",
    )

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 44.dp)
            .clickable(
                interactionSource = footerInteraction,
                indication = null,
                role = Role.Button,
                onClick = onOpenGitHub,
            ),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = "vdpi $versionLabel · $GITHUB_REPO_LABEL",
            style = VdpiTextStyles.caption,
            color = footerColor,
            textAlign = TextAlign.Center,
        )
    }
}

// ── Rows & Inputs ──

@Composable
private fun ChunkSizeRow(
    chunkSize: Int,
    onDecrease: () -> Unit,
    onIncrease: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val reduceMotion = LocalReduceMotion.current
    val canDecrease = chunkSize > 1
    val canIncrease = chunkSize < 64
    val dividerColor = palette.border.copy(alpha = palette.border.alpha * 0.7f)

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 52.dp)
            .padding(start = 16.dp, end = 12.dp, top = 4.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = "Chunk Size",
            style = VdpiTextStyles.rowTitle,
            color = palette.inkPrimary,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier
                .weight(1f)
                .padding(end = 12.dp),
        )

        // Capsule stepper: 34dp visual pill in surfaceRaised with 44dp hit targets
        Row(
            modifier = Modifier
                .drawBehind {
                    val pillHeight = 34.dp.toPx().coerceAtMost(size.height)
                    val top = (size.height - pillHeight) * 0.5f
                    val radius = pillHeight * 0.5f
                    drawRoundRect(
                        color = palette.surfaceRaised,
                        topLeft = Offset(0f, top),
                        size = Size(size.width, pillHeight),
                        cornerRadius = CornerRadius(radius, radius),
                    )
                },
            verticalAlignment = Alignment.CenterVertically,
        ) {
            StepperIconButton(
                isIncrease = false,
                contentDescription = "Decrease chunk size",
                enabled = canDecrease,
                onClick = onDecrease,
            )

            Box(
                modifier = Modifier
                    .width(0.5.dp)
                    .height(16.dp)
                    .background(dividerColor),
            )

            Box(
                modifier = Modifier
                    .widthIn(min = 52.dp)
                    .padding(horizontal = 6.dp),
                contentAlignment = Alignment.Center,
            ) {
                AnimatedContent(
                    targetState = chunkSize,
                    transitionSpec = {
                        if (reduceMotion) {
                            (fadeIn(tween(60)) togetherWith fadeOut(tween(60))).using(SizeTransform(clip = true))
                        } else {
                            val up = targetState > initialState
                            val enter = slideInVertically(
                                animationSpec = spring(
                                    stiffness = Spring.StiffnessMediumLow,
                                    dampingRatio = 0.85f,
                                ),
                            ) { h -> if (up) h / 2 else -h / 2 } + fadeIn(tween(140))
                            val exit = slideOutVertically(
                                animationSpec = tween(130),
                            ) { h -> if (up) -h / 2 else h / 2 } + fadeOut(tween(100))
                            (enter togetherWith exit).using(SizeTransform(clip = true))
                        }
                    },
                    label = "chunkSizeTabularSlide",
                ) { size ->
                    Text(
                        text = "$size B",
                        style = VdpiTextStyles.monoMetric.copy(fontWeight = FontWeight.Medium),
                        color = palette.inkPrimary,
                        textAlign = TextAlign.Center,
                        maxLines = 1,
                    )
                }
            }

            Box(
                modifier = Modifier
                    .width(0.5.dp)
                    .height(16.dp)
                    .background(dividerColor),
            )

            StepperIconButton(
                isIncrease = true,
                contentDescription = "Increase chunk size",
                enabled = canIncrease,
                onClick = onIncrease,
            )
        }
    }
}

@Composable
private fun StepperIconButton(
    isIncrease: Boolean,
    contentDescription: String,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val interaction = remember { MutableInteractionSource() }
    val isPressed by interaction.collectIsPressedAsState()
    val pressWash by animateColorAsState(
        targetValue = if (enabled && isPressed) {
            palette.inkPrimary.copy(alpha = 0.08f)
        } else {
            Color.Transparent
        },
        animationSpec = tween(durationMillis = if (isPressed) 60 else 160),
        label = "stepperPressWash",
    )

    Box(
        modifier = Modifier
            .size(44.dp)
            .clickable(
                enabled = enabled,
                interactionSource = interaction,
                indication = null,
                role = Role.Button,
                onClick = onClick,
            )
            .semantics { this.contentDescription = contentDescription },
        contentAlignment = Alignment.Center,
    ) {
        Box(
            modifier = Modifier
                .size(34.dp)
                .clip(CircleShape)
                .background(pressWash)
                .alpha(if (enabled) 1f else 0.32f),
            contentAlignment = Alignment.Center,
        ) {
            Canvas(modifier = Modifier.size(12.dp)) {
                val stroke = 1.7.dp.toPx()
                val inset = stroke * 0.5f
                val cy = size.height * 0.5f
                val cx = size.width * 0.5f
                drawLine(
                    color = palette.inkPrimary,
                    start = Offset(inset, cy),
                    end = Offset(size.width - inset, cy),
                    strokeWidth = stroke,
                    cap = StrokeCap.Round,
                )
                if (isIncrease) {
                    drawLine(
                        color = palette.inkPrimary,
                        start = Offset(cx, inset),
                        end = Offset(cx, size.height - inset),
                        strokeWidth = stroke,
                        cap = StrokeCap.Round,
                    )
                }
            }
        }
    }
}

@Composable
private fun BorderlessInputRow(
    value: String,
    placeholder: String,
    actionLabel: String,
    actionEnabled: Boolean,
    showCheckmark: Boolean,
    errorText: String?,
    onValueChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val actionInteraction = remember { MutableInteractionSource() }
    val actionPressed by actionInteraction.collectIsPressedAsState()
    val actionColor by animateColorAsState(
        targetValue = when {
            !actionEnabled -> palette.inkMuted.copy(alpha = 0.45f)
            actionPressed -> palette.accent.copy(alpha = 0.65f)
            else -> palette.accent
        },
        animationSpec = tween(140),
        label = "inputActionColor",
    )

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 16.dp, end = 6.dp, top = 3.dp, bottom = 3.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 46.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            BasicTextField(
                value = value,
                onValueChange = onValueChange,
                singleLine = true,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Uri,
                    autoCorrectEnabled = false,
                    imeAction = ImeAction.Done,
                ),
                keyboardActions = KeyboardActions(
                    onDone = { if (actionEnabled) onSubmit() },
                ),
                textStyle = VdpiTextStyles.rowTitle.copy(
                    color = palette.inkPrimary,
                    fontFeatureSettings = "tnum",
                    textDirection = TextDirection.Ltr,
                ),
                cursorBrush = SolidColor(palette.accent),
                modifier = Modifier
                    .weight(1f)
                    .padding(vertical = 10.dp),
                decorationBox = { innerTextField ->
                    Box(contentAlignment = Alignment.CenterStart) {
                        if (value.isEmpty()) {
                            Text(
                                text = placeholder,
                                style = VdpiTextStyles.rowTitle,
                                color = palette.inkMuted,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                        innerTextField()
                    }
                },
            )

            if (showCheckmark) {
                Box(
                    modifier = Modifier.padding(end = 10.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    SelectionCheckmark(visible = true)
                }
            } else {
                Box(
                    modifier = Modifier
                        .defaultMinSize(minWidth = 44.dp, minHeight = 44.dp)
                        .clickable(
                            enabled = actionEnabled,
                            interactionSource = actionInteraction,
                            indication = null,
                            role = Role.Button,
                            onClick = onSubmit,
                        )
                        .padding(horizontal = 10.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = actionLabel,
                        fontFamily = GeistSans,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 15.sp,
                        color = actionColor,
                        maxLines = 1,
                    )
                }
            }
        }

        AnimatedVisibility(
            visible = errorText != null,
            enter = fadeIn(tween(150)) + expandVertically(),
            exit = fadeOut(tween(120)) + shrinkVertically(),
        ) {
            Text(
                text = errorText.orEmpty(),
                style = VdpiTextStyles.caption,
                color = palette.danger,
                modifier = Modifier.padding(end = 10.dp, bottom = 8.dp),
            )
        }
    }
}

@Composable
private fun ToggleSettingRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val interaction = remember { MutableInteractionSource() }
    val isPressed by interaction.collectIsPressedAsState()
    val pressWash by animateColorAsState(
        targetValue = if (isPressed) palette.inkPrimary.copy(alpha = 0.06f) else Color.Transparent,
        animationSpec = tween(durationMillis = if (isPressed) 60 else 180),
        label = "toggleRowPressWash",
    )

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 50.dp)
            .background(pressWash)
            .toggleable(
                value = checked,
                interactionSource = interaction,
                indication = null,
                role = Role.Switch,
                onValueChange = { next ->
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onCheckedChange(next)
                },
            )
            .padding(horizontal = 16.dp, vertical = 11.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = VdpiTextStyles.rowTitle,
                color = palette.inkPrimary,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(2.dp))
            Text(
                text = subtitle,
                style = VdpiTextStyles.caption,
                color = palette.inkSecondary,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Spacer(Modifier.width(12.dp))
        PrecisionSwitch(
            checked = checked,
            onCheckedChange = null,
        )
    }
}

@Composable
private fun RemoveDomainButton(
    domain: String,
    onRemove: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val interaction = remember { MutableInteractionSource() }
    val isPressed by interaction.collectIsPressedAsState()
    val pressWash by animateColorAsState(
        targetValue = if (isPressed) palette.inkPrimary.copy(alpha = 0.08f) else Color.Transparent,
        animationSpec = tween(durationMillis = if (isPressed) 60 else 160),
        label = "removeDomainPressWash",
    )

    Box(
        modifier = Modifier
            .size(44.dp)
            .clickable(
                interactionSource = interaction,
                indication = null,
                role = Role.Button,
                onClick = onRemove,
            )
            .semantics { contentDescription = "Remove $domain" },
        contentAlignment = Alignment.CenterEnd,
    ) {
        Box(
            modifier = Modifier
                .size(30.dp)
                .clip(CircleShape)
                .background(pressWash),
            contentAlignment = Alignment.Center,
        ) {
            Canvas(modifier = Modifier.size(11.dp)) {
                val stroke = 1.7.dp.toPx()
                val inset = stroke * 0.5f
                drawLine(
                    color = palette.inkMuted,
                    start = Offset(inset, inset),
                    end = Offset(size.width - inset, size.height - inset),
                    strokeWidth = stroke,
                    cap = StrokeCap.Round,
                )
                drawLine(
                    color = palette.inkMuted,
                    start = Offset(size.width - inset, inset),
                    end = Offset(inset, size.height - inset),
                    strokeWidth = stroke,
                    cap = StrokeCap.Round,
                )
            }
        }
    }
}

// ── Glyphs ──

@Composable
private fun SelectionCheckmark(visible: Boolean) {
    val palette = VdpiThemeTokens.palette
    val progress by animateFloatAsState(
        targetValue = if (visible) 1f else 0f,
        animationSpec = tween(durationMillis = 160),
        label = "checkmarkVisibility",
    )

    Box(
        modifier = Modifier.size(20.dp),
        contentAlignment = Alignment.Center,
    ) {
        if (progress > 0.01f) {
            Canvas(
                modifier = Modifier
                    .size(16.dp)
                    .graphicsLayer {
                        alpha = progress
                        val scale = 0.85f + 0.15f * progress
                        scaleX = scale
                        scaleY = scale
                    },
            ) {
                val stroke = Stroke(
                    width = 2.1.dp.toPx(),
                    cap = StrokeCap.Round,
                    join = StrokeJoin.Round,
                )
                val path = Path().apply {
                    moveTo(size.width * 0.14f, size.height * 0.54f)
                    lineTo(size.width * 0.40f, size.height * 0.80f)
                    lineTo(size.width * 0.88f, size.height * 0.24f)
                }
                drawPath(path = path, color = palette.accent, style = stroke)
            }
        }
    }
}

@Composable
private fun ChevronRightGlyph(tint: Color) {
    val isRtl = LocalLayoutDirection.current == LayoutDirection.Rtl
    Canvas(
        modifier = Modifier
            .size(13.dp)
            .graphicsLayer { if (isRtl) scaleX = -1f },
    ) {
        val stroke = Stroke(
            width = 1.75.dp.toPx(),
            cap = StrokeCap.Round,
            join = StrokeJoin.Round,
        )
        val path = Path().apply {
            moveTo(size.width * 0.34f, size.height * 0.16f)
            lineTo(size.width * 0.68f, size.height * 0.50f)
            lineTo(size.width * 0.34f, size.height * 0.84f)
        }
        drawPath(path = path, color = tint, style = stroke)
    }
}

@Composable
private fun ArrowUpRightGlyph(tint: Color) {
    val isRtl = LocalLayoutDirection.current == LayoutDirection.Rtl
    Canvas(
        modifier = Modifier
            .size(13.dp)
            .graphicsLayer { if (isRtl) scaleX = -1f },
    ) {
        val strokeWidth = 1.7.dp.toPx()
        val stroke = Stroke(
            width = strokeWidth,
            cap = StrokeCap.Round,
            join = StrokeJoin.Round,
        )
        drawLine(
            color = tint,
            start = Offset(size.width * 0.22f, size.height * 0.78f),
            end = Offset(size.width * 0.78f, size.height * 0.22f),
            strokeWidth = strokeWidth,
            cap = StrokeCap.Round,
        )
        val head = Path().apply {
            moveTo(size.width * 0.32f, size.height * 0.22f)
            lineTo(size.width * 0.78f, size.height * 0.22f)
            lineTo(size.width * 0.78f, size.height * 0.68f)
        }
        drawPath(path = head, color = tint, style = stroke)
    }
}
