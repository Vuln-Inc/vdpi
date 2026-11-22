package com.vulninc.vdpi.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.SolidColor
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vulninc.vdpi.data.ThemePreference
import com.vulninc.vdpi.data.VdpiSettings
import com.vulninc.vdpi.engine.DesyncMode
import com.vulninc.vdpi.ui.components.HairlinePanel
import com.vulninc.vdpi.ui.components.HairlineRule
import com.vulninc.vdpi.ui.components.PrecisionSwitch
import com.vulninc.vdpi.ui.components.SectionOverline
import com.vulninc.vdpi.ui.components.SegmentedControl
import com.vulninc.vdpi.ui.theme.GeistMono
import com.vulninc.vdpi.ui.theme.GeistSans
import com.vulninc.vdpi.ui.theme.VdpiTextStyles
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens
import com.vulninc.vdpi.util.isValidBypassDomain
import com.vulninc.vdpi.util.isValidDnsInput
import com.vulninc.vdpi.util.sanitizeDomainInput

private val DNS_PRESET_ROWS = listOf(
    listOf("1.1.1.1" to "Cloudflare", "8.8.8.8" to "Google"),
    listOf("94.140.14.140" to "AdGuard", "9.9.9.9" to "Quad9"),
)

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
            .padding(horizontal = 20.dp, vertical = 16.dp),
    ) {
        Text(
            text = "Settings",
            style = VdpiTextStyles.screenTitle,
            color = palette.inkPrimary,
        )

        Spacer(Modifier.height(20.dp))

        // 1. DESYNC ENGINE
        SectionOverline("Desync Engine", modifier = Modifier.padding(start = 2.dp, bottom = 8.dp))
        HairlinePanel(radius = 14.dp) {
            DesyncMode.entries.forEachIndexed { idx, mode ->
                if (idx > 0) HairlineRule()
                val selected = settings.desyncMode == mode
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .selectable(
                            selected = selected,
                            role = Role.RadioButton,
                            onClick = {
                                if (!selected) {
                                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    onSetDesyncMode(mode)
                                }
                            },
                        )
                        .padding(horizontal = 16.dp, vertical = 13.dp),
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
                            .size(16.dp)
                            .clip(CircleShape)
                            .border(
                                width = if (selected) 5.dp else 1.5.dp,
                                color = if (selected) palette.inkPrimary else palette.borderStrong,
                                shape = CircleShape,
                            ),
                    )
                }
            }

            HairlineRule()

            // Chunk size stepper with full 44dp touch targets and bound-disabled feedback
            val canDecrease = settings.chunkSize > 1
            val canIncrease = settings.chunkSize < 64
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 16.dp, end = 10.dp, top = 8.dp, bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Chunk size",
                        style = VdpiTextStyles.rowTitle,
                        color = palette.inkPrimary,
                    )
                    Text(
                        text = "Initial TLS split segment size (1-64 B)",
                        style = VdpiTextStyles.caption,
                        color = palette.inkSecondary,
                    )
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    StepperButton(
                        label = "-",
                        contentDescription = "Decrease chunk size",
                        enabled = canDecrease,
                        onClick = {
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            onSetChunkSize((settings.chunkSize - 1).coerceAtLeast(1))
                        },
                    )
                    Text(
                        text = "${settings.chunkSize} B",
                        style = VdpiTextStyles.monoMetric,
                        color = palette.inkPrimary,
                        textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                        modifier = Modifier
                            .widthIn(min = 48.dp)
                            .padding(horizontal = 4.dp),
                    )
                    StepperButton(
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

            HairlineRule()

            ToggleSettingRow(
                title = "Block QUIC (UDP/443)",
                subtitle = "Redirects HTTP/3 apps onto DPI-bypassed TCP TLS",
                checked = settings.blockQuic,
                onCheckedChange = onSetBlockQuic,
            )
        }

        Spacer(Modifier.height(22.dp))

        // 2. DNS RESOLVER
        SectionOverline("DNS Resolver", modifier = Modifier.padding(start = 2.dp, bottom = 8.dp))
        HairlinePanel(radius = 14.dp) {
            ToggleSettingRow(
                title = "DNS-over-HTTPS (DoH)",
                subtitle = "Encrypted DNS with automatic failover",
                checked = settings.enableDoh,
                onCheckedChange = onSetEnableDoh,
            )
            HairlineRule()
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Primary upstream",
                    style = VdpiTextStyles.rowTitle,
                    color = palette.inkPrimary,
                )
                Spacer(Modifier.height(10.dp))

                // Uniform 2x2 grid of 48dp DNS preset tiles
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    DNS_PRESET_ROWS.forEach { row ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            row.forEach { (addr, name) ->
                                val active = settings.dnsAddr.equals(addr, ignoreCase = true)
                                val tileShape = RoundedCornerShape(10.dp)
                                Column(
                                    modifier = Modifier
                                        .weight(1f)
                                        .heightIn(min = 50.dp)
                                        .clip(tileShape)
                                        .background(if (active) palette.surfaceRaised else palette.canvas)
                                        .border(
                                            1.dp,
                                            if (active) palette.inkPrimary else palette.border,
                                            tileShape,
                                        )
                                        .selectable(
                                            selected = active,
                                            role = Role.RadioButton,
                                            onClick = {
                                                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                                customDnsInput = addr
                                                dnsError = null
                                                focusManager.clearFocus()
                                                if (!active) onSetDnsAddr(addr)
                                            },
                                        )
                                        .padding(horizontal = 12.dp, vertical = 8.dp),
                                    verticalArrangement = Arrangement.Center,
                                ) {
                                    Text(
                                        text = name,
                                        fontFamily = GeistSans,
                                        fontWeight = FontWeight.Medium,
                                        fontSize = 13.sp,
                                        color = if (active) palette.inkPrimary else palette.inkSecondary,
                                    )
                                    Text(
                                        text = addr,
                                        style = VdpiTextStyles.monoSmall,
                                        color = palette.inkMuted,
                                    )
                                }
                            }
                        }
                    }
                }

                Spacer(Modifier.height(12.dp))
                InlineInputRow(
                    value = customDnsInput,
                    placeholder = "IP or https://.../dns-query",
                    actionLabel = "Apply",
                    actionEnabled = dnsDirty,
                    errorText = dnsError,
                    onValueChange = {
                        customDnsInput = it
                        if (dnsError != null) dnsError = null
                    },
                    onSubmit = ::submitDns,
                )
            }
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
        SectionOverline("Bypass Rules", modifier = Modifier.padding(start = 2.dp, bottom = 8.dp))
        HairlinePanel(radius = 14.dp) {
            Column(modifier = Modifier.padding(16.dp)) {
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
                Spacer(Modifier.height(10.dp))
                InlineInputRow(
                    value = bypassInput,
                    placeholder = "*.example.com",
                    actionLabel = "Add",
                    actionEnabled = bypassInput.isNotBlank(),
                    errorText = bypassError,
                    onValueChange = {
                        bypassInput = it
                        if (bypassError != null) bypassError = null
                    },
                    onSubmit = ::submitBypass,
                )
                if (settings.bypassDomains.isNotEmpty()) {
                    Spacer(Modifier.height(12.dp))
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        settings.bypassDomains.forEach { domain ->
                            val chipShape = RoundedCornerShape(8.dp)
                            Row(
                                modifier = Modifier
                                    .heightIn(min = 44.dp)
                                    .clip(chipShape)
                                    .background(palette.surfaceRaised)
                                    .border(1.dp, palette.border, chipShape)
                                    .clickable(role = Role.Button) {
                                        focusManager.clearFocus()
                                        onRemoveBypassDomain(domain)
                                    }
                                    .semantics { contentDescription = "Remove $domain" }
                                    .padding(horizontal = 12.dp, vertical = 8.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(
                                    text = domain,
                                    style = VdpiTextStyles.monoSmall,
                                    color = palette.inkPrimary,
                                )
                                Spacer(Modifier.width(8.dp))
                                Text(
                                    text = "×",
                                    fontFamily = GeistMono,
                                    fontSize = 13.sp,
                                    color = palette.inkMuted,
                                )
                            }
                        }
                    }
                }
            }
        }

        Spacer(Modifier.height(22.dp))

        // 4. APPEARANCE & SYSTEM
        SectionOverline("System", modifier = Modifier.padding(start = 2.dp, bottom = 8.dp))
        HairlinePanel(radius = 14.dp) {
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
                title = "Always-on VPN",
                subtitle = "Open Android system VPN settings",
                trailing = "Open",
                onClick = onOpenAlwaysOnVpn,
            )
            HairlineRule()
            ActionSettingRow(
                title = "Reset adaptive cache",
                subtitle = "Clear learned TLS stages and in-memory DNS entries",
                trailing = "Reset",
                destructive = true,
                onClick = onClearCache,
            )
        }

        Spacer(Modifier.height(20.dp))

        Text(
            text = "vdpi v$engineVersion · Pure Rust userspace anti-DPI · MIT",
            style = VdpiTextStyles.monoSmall,
            color = palette.inkMuted,
            modifier = Modifier.padding(start = 2.dp),
        )

        Spacer(Modifier.height(18.dp))
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
            .padding(horizontal = 16.dp, vertical = 13.dp),
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
    destructive: Boolean = false,
    onClick: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(role = Role.Button, onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 13.dp),
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
        Text(
            text = trailing,
            style = VdpiTextStyles.monoSmall,
            fontWeight = if (destructive) FontWeight.Medium else FontWeight.Normal,
            color = if (destructive) palette.danger else palette.inkSecondary,
        )
    }
}

@Composable
private fun StepperButton(
    label: String,
    contentDescription: String,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val shape = RoundedCornerShape(8.dp)
    // 44dp touch target wrapping a crisp 34dp visual control
    Box(
        modifier = Modifier
            .size(44.dp)
            .clip(shape)
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick)
            .semantics { this.contentDescription = contentDescription },
        contentAlignment = Alignment.Center,
    ) {
        Box(
            modifier = Modifier
                .size(34.dp)
                .alpha(if (enabled) 1f else 0.35f)
                .clip(shape)
                .background(palette.surfaceRaised)
                .border(1.dp, palette.border, shape),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = label,
                fontFamily = GeistMono,
                fontWeight = FontWeight.Medium,
                fontSize = 15.sp,
                color = palette.inkPrimary,
            )
        }
    }
}

@Composable
private fun InlineInputRow(
    value: String,
    placeholder: String,
    actionLabel: String,
    actionEnabled: Boolean,
    errorText: String?,
    onValueChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val inputShape = RoundedCornerShape(9.dp)
    var focused by remember { mutableStateOf(false) }

    val fieldBorder by animateColorAsState(
        targetValue = when {
            errorText != null -> palette.danger
            focused -> palette.inkPrimary
            else -> palette.border
        },
        animationSpec = tween(160),
        label = "inputBorder",
    )

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
                cursorBrush = SolidColor(palette.inkPrimary),
                modifier = Modifier
                    .weight(1f)
                    .height(46.dp)
                    .onFocusChanged { focused = it.isFocused },
                decorationBox = { innerTextField ->
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .clip(inputShape)
                            .background(palette.canvas)
                            .border(1.dp, fieldBorder, inputShape)
                            .padding(horizontal = 12.dp),
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
                },
            )

            Box(
                modifier = Modifier
                    .height(46.dp)
                    .alpha(if (actionEnabled) 1f else 0.45f)
                    .clip(inputShape)
                    .background(if (actionEnabled) palette.primaryButtonBg else palette.surfaceRaised)
                    .border(
                        1.dp,
                        if (actionEnabled) palette.primaryButtonBg else palette.borderStrong,
                        inputShape,
                    )
                    .clickable(enabled = actionEnabled, role = Role.Button, onClick = onSubmit)
                    .padding(horizontal = 16.dp),
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

        if (errorText != null) {
            Spacer(Modifier.height(6.dp))
            Text(
                text = errorText,
                style = VdpiTextStyles.caption,
                color = palette.danger,
            )
        }
    }
}
