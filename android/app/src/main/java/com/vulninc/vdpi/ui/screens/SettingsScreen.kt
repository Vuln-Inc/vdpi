package com.vulninc.vdpi.ui.screens

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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
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
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens

private val DNS_PRESETS = listOf(
    "1.1.1.1" to "Cloudflare",
    "8.8.8.8" to "Google",
    "94.140.14.140" to "AdGuard",
    "9.9.9.9" to "Quad9",
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
    var customDnsInput by remember(settings.dnsAddr) { mutableStateOf(settings.dnsAddr) }
    var bypassInput by remember { mutableStateOf("") }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
    ) {
        Text(
            text = "Settings",
            fontFamily = GeistSans,
            fontWeight = FontWeight.SemiBold,
            fontSize = 20.sp,
            letterSpacing = (-0.4).sp,
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
                        .clickable { onSetDesyncMode(mode) }
                        .padding(horizontal = 16.dp, vertical = 13.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = mode.label,
                            fontFamily = GeistSans,
                            fontWeight = FontWeight.Medium,
                            fontSize = 14.sp,
                            color = palette.inkPrimary,
                        )
                        Spacer(Modifier.height(2.dp))
                        Text(
                            text = mode.summary,
                            fontFamily = GeistSans,
                            fontSize = 12.sp,
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

            // Chunk size stepper
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 13.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Chunk size",
                        fontFamily = GeistSans,
                        fontWeight = FontWeight.Medium,
                        fontSize = 14.sp,
                        color = palette.inkPrimary,
                    )
                    Text(
                        text = "Initial TLS split segment size",
                        fontFamily = GeistSans,
                        fontSize = 12.sp,
                        color = palette.inkSecondary,
                    )
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    StepperButton(
                        label = "-",
                        onClick = { onSetChunkSize((settings.chunkSize - 2).coerceAtLeast(2)) },
                    )
                    Text(
                        text = "${settings.chunkSize} B",
                        fontFamily = GeistMono,
                        fontWeight = FontWeight.Medium,
                        fontSize = 13.sp,
                        color = palette.inkPrimary,
                        modifier = Modifier.padding(horizontal = 12.dp),
                        style = TextStyle(fontFeatureSettings = "tnum"),
                    )
                    StepperButton(
                        label = "+",
                        onClick = { onSetChunkSize((settings.chunkSize + 2).coerceAtMost(64)) },
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
                subtitle = "Anti-poisoning RFC 8484 ring with sticky failover",
                checked = settings.enableDoh,
                onCheckedChange = onSetEnableDoh,
            )
            HairlineRule()
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Primary upstream",
                    fontFamily = GeistSans,
                    fontWeight = FontWeight.Medium,
                    fontSize = 14.sp,
                    color = palette.inkPrimary,
                )
                Spacer(Modifier.height(10.dp))
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    DNS_PRESETS.forEach { (addr, name) ->
                        val active = settings.dnsAddr.equals(addr, ignoreCase = true)
                        val chipShape = RoundedCornerShape(8.dp)
                        Row(
                            modifier = Modifier
                                .clip(chipShape)
                                .background(if (active) palette.surfaceRaised else palette.canvas)
                                .border(
                                    1.dp,
                                    if (active) palette.inkPrimary else palette.border,
                                    chipShape,
                                )
                                .clickable {
                                    customDnsInput = addr
                                    onSetDnsAddr(addr)
                                }
                                .padding(horizontal = 10.dp, vertical = 7.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                text = name,
                                fontFamily = GeistSans,
                                fontWeight = FontWeight.Medium,
                                fontSize = 12.sp,
                                color = if (active) palette.inkPrimary else palette.inkSecondary,
                            )
                            Spacer(Modifier.width(6.dp))
                            Text(
                                text = addr,
                                fontFamily = GeistMono,
                                fontSize = 11.sp,
                                color = palette.inkMuted,
                            )
                        }
                    }
                }
                Spacer(Modifier.height(10.dp))
                InlineInputRow(
                    value = customDnsInput,
                    placeholder = "IP or https://.../dns-query",
                    actionLabel = "Apply",
                    onValueChange = { customDnsInput = it },
                    onSubmit = { onSetDnsAddr(customDnsInput) },
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
                    fontFamily = GeistSans,
                    fontWeight = FontWeight.Medium,
                    fontSize = 14.sp,
                    color = palette.inkPrimary,
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text = "LAN subnets, government portals, and major banking WAFs are bypassed automatically.",
                    fontFamily = GeistSans,
                    fontSize = 12.sp,
                    lineHeight = 17.sp,
                    color = palette.inkSecondary,
                )
                Spacer(Modifier.height(10.dp))
                InlineInputRow(
                    value = bypassInput,
                    placeholder = "*.example.com",
                    actionLabel = "Add",
                    onValueChange = { bypassInput = it },
                    onSubmit = {
                        if (bypassInput.isNotBlank()) {
                            onAddBypassDomain(bypassInput)
                            bypassInput = ""
                        }
                    },
                )
                if (settings.bypassDomains.isNotEmpty()) {
                    Spacer(Modifier.height(10.dp))
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        settings.bypassDomains.forEach { domain ->
                            val chipShape = RoundedCornerShape(8.dp)
                            Row(
                                modifier = Modifier
                                    .clip(chipShape)
                                    .background(palette.surfaceRaised)
                                    .border(1.dp, palette.border, chipShape)
                                    .clickable { onRemoveBypassDomain(domain) }
                                    .padding(horizontal = 10.dp, vertical = 6.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(
                                    text = domain,
                                    fontFamily = GeistMono,
                                    fontSize = 11.sp,
                                    color = palette.inkPrimary,
                                )
                                Spacer(Modifier.width(6.dp))
                                Text(
                                    text = "×",
                                    fontFamily = GeistMono,
                                    fontSize = 12.sp,
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
                    fontFamily = GeistSans,
                    fontWeight = FontWeight.Medium,
                    fontSize = 14.sp,
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
                onClick = onClearCache,
            )
        }

        Spacer(Modifier.height(20.dp))

        Text(
            text = "vdpi v$engineVersion · Pure Rust userspace anti-DPI · MIT",
            fontFamily = GeistMono,
            fontSize = 11.sp,
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
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCheckedChange(!checked) }
            .padding(horizontal = 16.dp, vertical = 13.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                fontFamily = GeistSans,
                fontWeight = FontWeight.Medium,
                fontSize = 14.sp,
                color = palette.inkPrimary,
            )
            Spacer(Modifier.height(2.dp))
            Text(
                text = subtitle,
                fontFamily = GeistSans,
                fontSize = 12.sp,
                color = palette.inkSecondary,
            )
        }
        Spacer(Modifier.width(12.dp))
        PrecisionSwitch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            useSignalAccent = true,
        )
    }
}

@Composable
private fun ActionSettingRow(
    title: String,
    subtitle: String,
    trailing: String,
    onClick: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 13.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                fontFamily = GeistSans,
                fontWeight = FontWeight.Medium,
                fontSize = 14.sp,
                color = palette.inkPrimary,
            )
            Spacer(Modifier.height(2.dp))
            Text(
                text = subtitle,
                fontFamily = GeistSans,
                fontSize = 12.sp,
                color = palette.inkSecondary,
            )
        }
        Spacer(Modifier.width(12.dp))
        Text(
            text = trailing,
            fontFamily = GeistMono,
            fontSize = 11.sp,
            color = palette.inkSecondary,
        )
    }
}

@Composable
private fun StepperButton(
    label: String,
    onClick: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val shape = RoundedCornerShape(7.dp)
    Box(
        modifier = Modifier
            .size(30.dp)
            .clip(shape)
            .background(palette.surfaceRaised)
            .border(1.dp, palette.border, shape)
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = label,
            fontFamily = GeistMono,
            fontWeight = FontWeight.Medium,
            fontSize = 14.sp,
            color = palette.inkPrimary,
        )
    }
}

@Composable
private fun InlineInputRow(
    value: String,
    placeholder: String,
    actionLabel: String,
    onValueChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val inputShape = RoundedCornerShape(8.dp)
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Box(
            modifier = Modifier
                .weight(1f)
                .height(40.dp)
                .clip(inputShape)
                .background(palette.canvas)
                .border(1.dp, palette.border, inputShape)
                .padding(horizontal = 12.dp),
            contentAlignment = Alignment.CenterStart,
        ) {
            if (value.isEmpty()) {
                Text(
                    text = placeholder,
                    fontFamily = GeistMono,
                    fontSize = 12.sp,
                    color = palette.inkMuted,
                )
            }
            BasicTextField(
                value = value,
                onValueChange = onValueChange,
                singleLine = true,
                textStyle = TextStyle(
                    fontFamily = GeistMono,
                    fontSize = 12.sp,
                    color = palette.inkPrimary,
                ),
                cursorBrush = SolidColor(palette.inkPrimary),
                modifier = Modifier.fillMaxWidth(),
            )
        }

        Box(
            modifier = Modifier
                .height(40.dp)
                .clip(inputShape)
                .background(palette.surfaceRaised)
                .border(1.dp, palette.borderStrong, inputShape)
                .clickable(onClick = onSubmit)
                .padding(horizontal = 14.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = actionLabel,
                fontFamily = GeistSans,
                fontWeight = FontWeight.Medium,
                fontSize = 12.sp,
                color = palette.inkPrimary,
            )
        }
    }
}
