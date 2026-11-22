package com.vulninc.vdpi.ui.screens

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.SizeTransform
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathOperation
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vulninc.vdpi.data.ThemePreference
import com.vulninc.vdpi.data.VdpiSettings
import com.vulninc.vdpi.engine.DesyncMode
import com.vulninc.vdpi.ui.components.FloatingGlassIconButton
import com.vulninc.vdpi.ui.components.HairlineRule
import com.vulninc.vdpi.ui.components.LiquidGlassCapsule
import com.vulninc.vdpi.ui.components.LiquidGlassCard
import com.vulninc.vdpi.ui.components.LocalBottomChromePadding
import com.vulninc.vdpi.ui.components.LocalTopOverlayPadding
import com.vulninc.vdpi.ui.components.PrecisionSwitch
import com.vulninc.vdpi.ui.components.SectionOverline
import com.vulninc.vdpi.ui.components.SegmentedControl
import com.vulninc.vdpi.ui.components.VdpiMotion
import com.vulninc.vdpi.ui.components.springPress
import com.vulninc.vdpi.ui.theme.GeistMono
import com.vulninc.vdpi.ui.theme.GeistSans
import com.vulninc.vdpi.ui.theme.VdpiTextStyles
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens
import com.vulninc.vdpi.util.isValidBypassDomain
import com.vulninc.vdpi.util.isValidDnsInput
import com.vulninc.vdpi.util.sanitizeDomainInput
import kotlin.math.cos
import kotlin.math.sin

private val DNS_PRESET_ROWS = listOf(
    listOf("1.1.1.1" to "Cloudflare", "8.8.8.8" to "Google"),
    listOf("94.140.14.140" to "AdGuard", "9.9.9.9" to "Quad9"),
)

private fun nextTheme(current: ThemePreference): ThemePreference = when (current) {
    ThemePreference.SYSTEM -> ThemePreference.DARK
    ThemePreference.DARK -> ThemePreference.LIGHT
    ThemePreference.LIGHT -> ThemePreference.SYSTEM
}

@OptIn(ExperimentalLayoutApi::class)
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
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val focusManager = LocalFocusManager.current
    val bottomChromePadding = LocalBottomChromePadding.current
    val topOverlayPadding by animateDpAsState(
        targetValue = LocalTopOverlayPadding.current,
        animationSpec = VdpiMotion.tabLensSpring,
        label = "settingsTopOverlay",
    )

    var customDnsInput by remember(settings.dnsAddr) { mutableStateOf(settings.dnsAddr) }
    var dnsError by remember(settings.dnsAddr) { mutableStateOf<String?>(null) }

    var bypassInput by remember { mutableStateOf("") }
    var bypassError by remember { mutableStateOf<String?>(null) }

    val dnsTrimmed = customDnsInput.trim()
    val dnsDirty = dnsTrimmed.isNotEmpty() && !dnsTrimmed.equals(settings.dnsAddr, ignoreCase = true)

    fun submitDns() {
        val candidate = customDnsInput.trim()
        if (!isValidDnsInput(candidate)) {
            dnsError = "Enter a valid IPv4, IPv6, or https:// DoH URL"
            return
        }
        dnsError = null
        focusManager.clearFocus()
        if (!candidate.equals(settings.dnsAddr, ignoreCase = true)) {
            onSetDnsAddr(candidate)
        }
    }

    fun submitBypass() {
        val cleaned = sanitizeDomainInput(bypassInput)
        if (!isValidBypassDomain(cleaned)) {
            bypassError = "Enter a valid domain (e.g. example.com or *.bank.org)"
            return
        }
        if (cleaned in settings.bypassDomains) {
            bypassError = "$cleaned is already in the bypass list"
            return
        }
        bypassError = null
        bypassInput = ""
        focusManager.clearFocus()
        onAddBypassDomain(cleaned)
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .statusBarsPadding()
            .padding(horizontal = 20.dp),
    ) {
        Spacer(Modifier.height(topOverlayPadding + 14.dp))

        // Editorial header + circular frosted theme cycler button
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Settings",
                    style = VdpiTextStyles.pageTitle,
                    color = palette.inkPrimary,
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text = "Engine, DNS & routing profile",
                    style = VdpiTextStyles.caption,
                    color = palette.inkSecondary,
                )
            }

            Spacer(Modifier.width(12.dp))

            FloatingGlassIconButton(
                onClick = { onSetTheme(nextTheme(settings.theme)) },
                contentDescription = "Theme: ${settings.theme.label}. Tap to cycle.",
                size = 44.dp,
            ) {
                AnimatedContent(
                    targetState = settings.theme,
                    transitionSpec = {
                        (fadeIn(tween(180)) + scaleIn(initialScale = 0.8f, animationSpec = tween(180))) togetherWith
                            (fadeOut(tween(120)) + scaleOut(targetScale = 0.8f, animationSpec = tween(120)))
                    },
                    label = "themeIconTransition",
                ) { theme ->
                    ThemeGlyph(theme = theme, tint = palette.inkPrimary)
                }
            }
        }

        Spacer(Modifier.height(22.dp))

        // 1. DESYNC ENGINE
        SectionOverline("DESYNC ENGINE", modifier = Modifier.padding(start = 4.dp, bottom = 8.dp))
        LiquidGlassCard(
            modifier = Modifier.fillMaxWidth(),
            radius = 22.dp,
            elevated = true,
        ) {
            DesyncMode.entries.forEachIndexed { idx, mode ->
                if (idx > 0) HairlineRule()
                DesyncModeRow(
                    mode = mode,
                    selected = settings.desyncMode == mode,
                    onSelect = {
                        if (settings.desyncMode != mode) {
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            onSetDesyncMode(mode)
                        }
                    },
                )
            }

            HairlineRule()

            // Chunk size stepper with circular 36dp glass buttons (44dp touch targets) + sliding numeric counter
            val canDecrease = settings.chunkSize > 1
            val canIncrease = settings.chunkSize < 64
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 16.dp, end = 10.dp, top = 10.dp, bottom = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Chunk size",
                        style = VdpiTextStyles.rowTitle,
                        color = palette.inkPrimary,
                    )
                    Spacer(Modifier.height(2.dp))
                    Text(
                        text = "Initial TLS split segment size (1-64 B)",
                        style = VdpiTextStyles.caption,
                        color = palette.inkSecondary,
                    )
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    GlassStepperButton(
                        label = "-",
                        contentDescription = "Decrease chunk size",
                        enabled = canDecrease,
                        onClick = {
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            onSetChunkSize((settings.chunkSize - 1).coerceAtLeast(1))
                        },
                    )

                    Box(
                        modifier = Modifier
                            .widthIn(min = 52.dp)
                            .padding(horizontal = 2.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        AnimatedContent(
                            targetState = settings.chunkSize,
                            transitionSpec = {
                                val up = targetState > initialState
                                val enter = slideInVertically(
                                    animationSpec = spring(
                                        stiffness = Spring.StiffnessMediumLow,
                                        dampingRatio = 0.85f,
                                    ),
                                ) { h -> if (up) h / 2 else -h / 2 } + fadeIn(tween(150))
                                val exit = slideOutVertically(
                                    animationSpec = tween(140),
                                ) { h -> if (up) -h / 2 else h / 2 } + fadeOut(tween(110))
                                (enter togetherWith exit).using(SizeTransform(clip = true))
                            },
                            label = "chunkSizeNumericSlide",
                        ) { size ->
                            Text(
                                text = "$size B",
                                style = VdpiTextStyles.monoMetric,
                                color = palette.inkPrimary,
                                textAlign = TextAlign.Center,
                            )
                        }
                    }

                    GlassStepperButton(
                        label = "+",
                        contentDescription = "Increase chunk size",
                        enabled = canIncrease,
                        onClick = {
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            onSetChunkSize((settings.chunkSize + 1).coerceAtMost(64))
                        },
                    )
                }
            }
        }

        Spacer(Modifier.height(22.dp))

        // 2. DNS RESOLVER
        SectionOverline("DNS RESOLVER", modifier = Modifier.padding(start = 4.dp, bottom = 8.dp))
        LiquidGlassCard(
            modifier = Modifier.fillMaxWidth(),
            radius = 22.dp,
            elevated = true,
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Primary upstream",
                    style = VdpiTextStyles.rowTitle,
                    color = palette.inkPrimary,
                )
                Spacer(Modifier.height(10.dp))

                // 2x2 grid of nested glass DNS preset tiles
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    DNS_PRESET_ROWS.forEach { row ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            row.forEach { (addr, name) ->
                                val active = settings.dnsAddr.equals(addr, ignoreCase = true)
                                DnsPresetTile(
                                    name = name,
                                    address = addr,
                                    active = active,
                                    onClick = {
                                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                        customDnsInput = addr
                                        dnsError = null
                                        focusManager.clearFocus()
                                        if (!active) onSetDnsAddr(addr)
                                    },
                                    modifier = Modifier.weight(1f),
                                )
                            }
                        }
                    }
                }

                Spacer(Modifier.height(12.dp))

                PillInputRow(
                    value = customDnsInput,
                    placeholder = "IP or https://.../dns-query",
                    actionLabel = "Save",
                    actionEnabled = dnsDirty,
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
            }

            HairlineRule()

            ToggleSettingRow(
                title = "DNS-over-HTTPS (DoH)",
                subtitle = "Encrypted DNS with automatic failover",
                checked = settings.enableDoh,
                onCheckedChange = onSetEnableDoh,
            )

            HairlineRule()

            ToggleSettingRow(
                title = "Block QUIC (UDP/443)",
                subtitle = "Redirects HTTP/3 apps onto DPI-bypassed TCP TLS",
                checked = settings.blockQuic,
                onCheckedChange = onSetBlockQuic,
            )

            HairlineRule()

            ToggleSettingRow(
                title = "IPv4 only",
                subtitle = "Skip AAAA queries and IPv6 tunnel routes",
                checked = settings.ipv4Only,
                onCheckedChange = onSetIpv4Only,
            )
        }

        Spacer(Modifier.height(22.dp))

        // 3. BYPASS RULES
        SectionOverline("BYPASS RULES", modifier = Modifier.padding(start = 4.dp, bottom = 8.dp))
        LiquidGlassCard(
            modifier = Modifier.fillMaxWidth(),
            radius = 22.dp,
            elevated = true,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
            ) {
                Text(
                    text = "Custom domains",
                    style = VdpiTextStyles.rowTitle,
                    color = palette.inkPrimary,
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text = "LAN subnets, government portals, and major banking sites are bypassed automatically.",
                    style = VdpiTextStyles.caption,
                    color = palette.inkSecondary,
                )
                Spacer(Modifier.height(12.dp))
                PillInputRow(
                    value = bypassInput,
                    placeholder = "*.example.com",
                    actionLabel = "Add",
                    actionEnabled = bypassInput.isNotBlank(),
                    errorText = bypassError,
                    onValueChange = { next ->
                        bypassInput = next
                        if (bypassError != null) bypassError = null
                    },
                    onSubmit = ::submitBypass,
                )

                AnimatedVisibility(
                    visible = settings.bypassDomains.isNotEmpty(),
                    enter = fadeIn(tween(180)) + expandVertically(),
                    exit = fadeOut(tween(140)) + shrinkVertically(),
                ) {
                    Column {
                        Spacer(Modifier.height(12.dp))
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            settings.bypassDomains.forEach { domain ->
                                BypassDomainChip(
                                    domain = domain,
                                    onRemove = {
                                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                        focusManager.clearFocus()
                                        onRemoveBypassDomain(domain)
                                    },
                                )
                            }
                        }
                    }
                }
            }
        }

        Spacer(Modifier.height(22.dp))

        // 4. SYSTEM
        SectionOverline("SYSTEM", modifier = Modifier.padding(start = 4.dp, bottom = 8.dp))
        LiquidGlassCard(
            modifier = Modifier.fillMaxWidth(),
            radius = 22.dp,
            elevated = true,
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Appearance",
                    style = VdpiTextStyles.rowTitle,
                    color = palette.inkPrimary,
                )
                Spacer(Modifier.height(10.dp))
                SegmentedControl(
                    options = ThemePreference.entries,
                    selected = settings.theme,
                    labelFor = { it.label },
                    onSelect = onSetTheme,
                )
            }

            HairlineRule()

            ActionSettingRow(
                title = "Clear engine cache",
                subtitle = "Reset learned TLS stages and in-memory DNS entries",
                trailing = "Clear",
                destructive = true,
                showChevron = false,
                onClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onClearCache()
                },
            )

            HairlineRule()

            ActionSettingRow(
                title = "System VPN settings",
                subtitle = "Configure Always-on VPN in Android settings",
                trailing = "Open",
                destructive = false,
                showChevron = true,
                onClick = onOpenAlwaysOnVpn,
            )
        }

        Spacer(Modifier.height(18.dp))

        Text(
            text = "vdpi v$engineVersion · Pure Rust userspace anti-DPI · MIT",
            style = VdpiTextStyles.monoSmall,
            color = palette.inkMuted,
            modifier = Modifier.padding(start = 4.dp),
        )

        Spacer(Modifier.height(bottomChromePadding + 12.dp))
    }
}

@Composable
private fun DesyncModeRow(
    mode: DesyncMode,
    selected: Boolean,
    onSelect: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val interaction = remember { MutableInteractionSource() }

    val highlightBg by animateColorAsState(
        targetValue = if (selected) {
            palette.accentTint.copy(alpha = if (palette.isDark) 0.55f else 0.45f)
        } else {
            Color.Transparent
        },
        animationSpec = tween(200),
        label = "modeRowBg",
    )
    val ringWidth by animateDpAsState(
        targetValue = if (selected) 5.5.dp else 1.5.dp,
        animationSpec = VdpiMotion.tabLensSpring,
        label = "modeRingWidth",
    )
    val ringColor by animateColorAsState(
        targetValue = if (selected) palette.accent else palette.borderStrong,
        animationSpec = tween(180),
        label = "modeRingColor",
    )

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(highlightBg)
            .springPress(interactionSource = interaction, pressedScale = 0.985f)
            .selectable(
                selected = selected,
                interactionSource = interaction,
                indication = null,
                role = Role.RadioButton,
                onClick = onSelect,
            )
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = mode.label,
                style = VdpiTextStyles.rowTitle,
                color = palette.inkPrimary,
            )
            Spacer(Modifier.height(2.dp))
            Text(
                text = mode.summary,
                style = VdpiTextStyles.caption,
                color = palette.inkSecondary,
            )
        }
        Spacer(Modifier.width(12.dp))
        Box(
            modifier = Modifier
                .size(18.dp)
                .clip(CircleShape)
                .border(width = ringWidth, color = ringColor, shape = CircleShape),
        )
    }
}

@Composable
private fun DnsPresetTile(
    name: String,
    address: String,
    active: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    val interaction = remember { MutableInteractionSource() }
    val tileShape = RoundedCornerShape(14.dp)

    val tileBg by animateColorAsState(
        targetValue = if (active) palette.signalTint else palette.glassFillSubtle,
        animationSpec = tween(180),
        label = "dnsTileBg",
    )
    val tileBorder by animateColorAsState(
        targetValue = if (active) palette.signalBorder else palette.border,
        animationSpec = tween(180),
        label = "dnsTileBorder",
    )
    val dotScale by animateFloatAsState(
        targetValue = if (active) 1f else 0f,
        animationSpec = VdpiMotion.toggleSpring,
        label = "dnsDotScale",
    )

    Column(
        modifier = modifier
            .heightIn(min = 56.dp)
            .springPress(interactionSource = interaction, pressedScale = 0.96f)
            .clip(tileShape)
            .background(tileBg)
            .border(1.dp, tileBorder, tileShape)
            .selectable(
                selected = active,
                interactionSource = interaction,
                indication = null,
                role = Role.RadioButton,
                onClick = onClick,
            )
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = name,
                fontFamily = GeistSans,
                fontWeight = if (active) FontWeight.SemiBold else FontWeight.Medium,
                fontSize = 13.sp,
                color = if (active) palette.inkPrimary else palette.inkSecondary,
            )
            Box(
                modifier = Modifier
                    .size(7.dp)
                    .graphicsLayer {
                        scaleX = dotScale
                        scaleY = dotScale
                        alpha = dotScale
                    }
                    .shadow(
                        elevation = 4.dp,
                        shape = CircleShape,
                        clip = false,
                        ambientColor = palette.signalGlow,
                        spotColor = palette.signalGlow,
                    )
                    .clip(CircleShape)
                    .background(palette.signal),
            )
        }
        Spacer(Modifier.height(2.dp))
        Text(
            text = address,
            style = VdpiTextStyles.monoSmall,
            color = if (active) palette.inkPrimary else palette.inkMuted,
        )
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
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .toggleable(
                value = checked,
                role = Role.Switch,
                onValueChange = { next ->
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onCheckedChange(next)
                },
            )
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = VdpiTextStyles.rowTitle,
                color = palette.inkPrimary,
            )
            Spacer(Modifier.height(2.dp))
            Text(
                text = subtitle,
                style = VdpiTextStyles.caption,
                color = palette.inkSecondary,
            )
        }
        Spacer(Modifier.width(12.dp))
        PrecisionSwitch(
            checked = checked,
            onCheckedChange = null,
            useSignalAccent = true,
        )
    }
}

@Composable
private fun ActionSettingRow(
    title: String,
    subtitle: String,
    trailing: String,
    destructive: Boolean,
    showChevron: Boolean,
    onClick: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val interaction = remember { MutableInteractionSource() }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .springPress(interactionSource = interaction, pressedScale = 0.985f)
            .clickable(
                interactionSource = interaction,
                indication = null,
                role = Role.Button,
                onClick = onClick,
            )
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = VdpiTextStyles.rowTitle,
                color = palette.inkPrimary,
            )
            Spacer(Modifier.height(2.dp))
            Text(
                text = subtitle,
                style = VdpiTextStyles.caption,
                color = palette.inkSecondary,
            )
        }
        Spacer(Modifier.width(12.dp))
        LiquidGlassCapsule(
            rimTint = if (destructive) palette.danger else null,
            fillTint = if (destructive) palette.dangerTint else palette.glassFillSubtle,
            elevated = false,
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(5.dp),
            ) {
                Text(
                    text = trailing,
                    style = VdpiTextStyles.monoSmall,
                    fontWeight = FontWeight.Medium,
                    color = if (destructive) palette.danger else palette.inkPrimary,
                )
                if (showChevron) {
                    ChevronRightGlyph(tint = palette.inkSecondary)
                }
            }
        }
    }
}

@Composable
private fun GlassStepperButton(
    label: String,
    contentDescription: String,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val interaction = remember { MutableInteractionSource() }
    // 44dp touch target wrapping a circular 36dp frosted glass button
    Box(
        modifier = Modifier
            .size(44.dp)
            .springPress(interactionSource = interaction, pressedScale = 0.92f)
            .clip(CircleShape)
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
        LiquidGlassCapsule(
            modifier = Modifier
                .size(36.dp)
                .alpha(if (enabled) 1f else 0.36f),
            fillTint = palette.glassFillSubtle,
            elevated = false,
        ) {
            Text(
                text = label,
                fontFamily = GeistMono,
                fontWeight = FontWeight.Medium,
                fontSize = 16.sp,
                color = palette.inkPrimary,
            )
        }
    }
}

@Composable
private fun PillInputRow(
    value: String,
    placeholder: String,
    actionLabel: String,
    actionEnabled: Boolean,
    errorText: String?,
    onValueChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val actionInteraction = remember { MutableInteractionSource() }
    var focused by remember { mutableStateOf(false) }

    val focusProgress by animateFloatAsState(
        targetValue = if (focused) 1f else 0f,
        animationSpec = tween(160),
        label = "pillFocusProgress",
    )
    val fieldRimTint = when {
        errorText != null -> palette.danger
        focusProgress > 0.01f -> lerp(palette.glassRimTop, palette.accent, focusProgress)
        else -> null
    }

    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
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
                    onDone = { onSubmit() },
                ),
                textStyle = TextStyle(
                    fontFamily = GeistMono,
                    fontSize = 12.sp,
                    color = palette.inkPrimary,
                ),
                cursorBrush = SolidColor(palette.accent),
                modifier = Modifier
                    .weight(1f)
                    .height(46.dp)
                    .onFocusChanged { focused = it.isFocused },
                decorationBox = { innerTextField ->
                    LiquidGlassCapsule(
                        modifier = Modifier.fillMaxSize(),
                        rimTint = fieldRimTint,
                        fillTint = palette.glassFillSubtle,
                        elevated = false,
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(horizontal = 16.dp),
                            contentAlignment = Alignment.CenterStart,
                        ) {
                            if (value.isEmpty()) {
                                Text(
                                    text = placeholder,
                                    style = VdpiTextStyles.monoSmall,
                                    fontSize = 12.sp,
                                    color = palette.inkMuted,
                                )
                            }
                            innerTextField()
                        }
                    }
                },
            )

            Box(
                modifier = Modifier
                    .height(46.dp)
                    .alpha(if (actionEnabled) 1f else 0.45f)
                    .springPress(interactionSource = actionInteraction, pressedScale = 0.94f)
                    .clip(CircleShape)
                    .background(if (actionEnabled) palette.primaryButtonBg else palette.glassFillSubtle)
                    .border(
                        width = 1.dp,
                        color = if (actionEnabled) palette.primaryButtonBg else palette.borderStrong,
                        shape = CircleShape,
                    )
                    .clickable(
                        enabled = actionEnabled,
                        interactionSource = actionInteraction,
                        indication = null,
                        role = Role.Button,
                        onClick = onSubmit,
                    )
                    .padding(horizontal = 18.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = actionLabel,
                    fontFamily = GeistSans,
                    fontWeight = FontWeight.Medium,
                    fontSize = 13.sp,
                    color = if (actionEnabled) palette.primaryButtonInk else palette.inkSecondary,
                )
            }
        }

        AnimatedVisibility(
            visible = errorText != null,
            enter = fadeIn(tween(150)) + expandVertically(),
            exit = fadeOut(tween(120)) + shrinkVertically(),
        ) {
            Column {
                Spacer(Modifier.height(6.dp))
                Text(
                    text = errorText.orEmpty(),
                    style = VdpiTextStyles.caption,
                    color = palette.danger,
                    modifier = Modifier.padding(start = 6.dp),
                )
            }
        }
    }
}

@Composable
private fun BypassDomainChip(
    domain: String,
    onRemove: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val interaction = remember { MutableInteractionSource() }

    LiquidGlassCapsule(
        modifier = Modifier
            .heightIn(min = 44.dp)
            .springPress(interactionSource = interaction, pressedScale = 0.94f)
            .clip(CircleShape)
            .clickable(
                interactionSource = interaction,
                indication = null,
                role = Role.Button,
                onClick = onRemove,
            )
            .semantics { contentDescription = "Remove $domain" },
        fillTint = palette.glassFillSubtle,
        elevated = false,
    ) {
        Row(
            modifier = Modifier.padding(start = 13.dp, end = 10.dp, top = 8.dp, bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = domain,
                style = VdpiTextStyles.monoSmall,
                color = palette.inkPrimary,
            )
            Spacer(Modifier.width(8.dp))
            Box(
                modifier = Modifier
                    .size(20.dp)
                    .clip(CircleShape)
                    .background(palette.border.copy(alpha = 0.35f)),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = "×",
                    fontFamily = GeistMono,
                    fontWeight = FontWeight.Medium,
                    fontSize = 12.sp,
                    color = palette.inkSecondary,
                )
            }
        }
    }
}

@Composable
private fun ThemeGlyph(
    theme: ThemePreference,
    tint: Color,
) {
    Canvas(modifier = Modifier.size(18.dp)) {
        val w = size.width
        val h = size.height
        val cx = w * 0.5f
        val cy = h * 0.5f
        val strokeWidth = 1.6.dp.toPx()

        when (theme) {
            ThemePreference.LIGHT -> {
                val coreR = w * 0.21f
                drawCircle(
                    color = tint,
                    radius = coreR,
                    center = Offset(cx, cy),
                    style = Stroke(width = strokeWidth),
                )
                val innerR = w * 0.34f
                val outerR = w * 0.46f
                for (i in 0 until 8) {
                    val angle = Math.toRadians(i * 45.0)
                    val dx = cos(angle).toFloat()
                    val dy = sin(angle).toFloat()
                    drawLine(
                        color = tint,
                        start = Offset(cx + dx * innerR, cy + dy * innerR),
                        end = Offset(cx + dx * outerR, cy + dy * outerR),
                        strokeWidth = strokeWidth,
                        cap = StrokeCap.Round,
                    )
                }
            }

            ThemePreference.DARK -> {
                val outer = Path().apply {
                    addOval(
                        Rect(
                            offset = Offset(w * 0.14f, h * 0.14f),
                            size = Size(w * 0.72f, h * 0.72f),
                        ),
                    )
                }
                val cutout = Path().apply {
                    addOval(
                        Rect(
                            offset = Offset(w * 0.34f, h * 0.06f),
                            size = Size(w * 0.64f, h * 0.64f),
                        ),
                    )
                }
                val crescent = Path.combine(PathOperation.Difference, outer, cutout)
                drawPath(
                    path = crescent,
                    color = tint,
                    style = Stroke(
                        width = strokeWidth,
                        cap = StrokeCap.Round,
                        join = StrokeJoin.Round,
                    ),
                )
            }

            ThemePreference.SYSTEM -> {
                val r = w * 0.38f
                drawCircle(
                    color = tint,
                    radius = r,
                    center = Offset(cx, cy),
                    style = Stroke(width = strokeWidth),
                )
                drawArc(
                    color = tint,
                    startAngle = -90f,
                    sweepAngle = 180f,
                    useCenter = true,
                    topLeft = Offset(cx - r, cy - r),
                    size = Size(r * 2f, r * 2f),
                )
            }
        }
    }
}

@Composable
private fun ChevronRightGlyph(tint: Color) {
    Canvas(modifier = Modifier.size(11.dp)) {
        val stroke = Stroke(
            width = 1.5.dp.toPx(),
            cap = StrokeCap.Round,
            join = StrokeJoin.Round,
        )
        val path = Path().apply {
            moveTo(size.width * 0.32f, size.height * 0.18f)
            lineTo(size.width * 0.68f, size.height * 0.50f)
            lineTo(size.width * 0.32f, size.height * 0.82f)
        }
        drawPath(path = path, color = tint, style = stroke)
    }
}
