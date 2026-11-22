package com.vulninc.vdpi.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vulninc.vdpi.data.SplitTunnelMode
import com.vulninc.vdpi.data.VdpiSettings
import com.vulninc.vdpi.ui.InstalledAppItem
import com.vulninc.vdpi.ui.components.HairlineRule
import com.vulninc.vdpi.ui.components.PrecisionSwitch
import com.vulninc.vdpi.ui.components.SegmentedControl
import com.vulninc.vdpi.ui.theme.GeistMono
import com.vulninc.vdpi.ui.theme.GeistSans
import com.vulninc.vdpi.ui.theme.VdpiTextStyles
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens
import java.util.Locale

private enum class AppFilter {
    ALL,
    SELECTED,
}

@Composable
fun AppsScreen(
    settings: VdpiSettings,
    apps: List<InstalledAppItem>,
    loading: Boolean,
    onSetSplitMode: (SplitTunnelMode) -> Unit,
    onTogglePackage: (String) -> Unit,
    onClearPackages: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    val focusManager = LocalFocusManager.current
    var query by rememberSaveable { mutableStateOf("") }
    var showSystem by rememberSaveable { mutableStateOf(false) }
    var activeFilter by rememberSaveable { mutableStateOf(AppFilter.ALL) }
    var searchFocused by remember { mutableStateOf(false) }

    // Stable alphabetical order during interaction so toggling never yanks a row under the thumb.
    val filtered = remember(apps, query, showSystem, activeFilter, settings.splitPackages) {
        val q = query.trim().lowercase(Locale.ROOT)
        apps.filter { app ->
            val inSelected = app.packageName in settings.splitPackages
            val passesFilter = when (activeFilter) {
                AppFilter.ALL -> showSystem || !app.isSystem || inSelected
                AppFilter.SELECTED -> inSelected
            }
            val passesQuery = q.isEmpty() ||
                app.label.lowercase(Locale.ROOT).contains(q) ||
                app.packageName.lowercase(Locale.ROOT).contains(q)
            passesFilter && passesQuery
        }
    }

    val searchBorder by animateColorAsState(
        targetValue = if (searchFocused) palette.inkPrimary else palette.border,
        animationSpec = tween(160),
        label = "searchBorder",
    )

    Column(modifier = modifier.fillMaxSize()) {
        Column(modifier = Modifier.padding(horizontal = 20.dp)) {
            Spacer(Modifier.height(16.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = "Split Tunnel",
                    style = VdpiTextStyles.screenTitle,
                    color = palette.inkPrimary,
                )
                Text(
                    text = "${settings.splitPackages.size} selected",
                    style = VdpiTextStyles.monoSmall,
                    color = palette.inkMuted,
                )
            }

            Spacer(Modifier.height(14.dp))

            SegmentedControl(
                options = SplitTunnelMode.entries,
                selected = settings.splitTunnelMode,
                labelFor = { it.label },
                onSelect = onSetSplitMode,
            )

            Spacer(Modifier.height(8.dp))

            Text(
                text = when (settings.splitTunnelMode) {
                    SplitTunnelMode.BYPASS_SELECTED ->
                        "Selected apps bypass vdpi directly (useful for local banking or LAN tools)."
                    SplitTunnelMode.ONLY_SELECTED ->
                        "Only selected apps route through vdpi. If none are selected, all apps are protected."
                },
                style = VdpiTextStyles.caption,
                color = palette.inkSecondary,
            )

            Spacer(Modifier.height(14.dp))

            // Full-area 48dp hairline search field via decorationBox (zero dead touch zones)
            val searchShape = RoundedCornerShape(10.dp)
            BasicTextField(
                value = query,
                onValueChange = { query = it },
                singleLine = true,
                keyboardOptions = KeyboardOptions(
                    autoCorrectEnabled = false,
                    imeAction = ImeAction.Search,
                ),
                keyboardActions = KeyboardActions(
                    onSearch = { focusManager.clearFocus() },
                ),
                textStyle = TextStyle(
                    fontFamily = GeistSans,
                    fontSize = 13.sp,
                    color = palette.inkPrimary,
                ),
                cursorBrush = SolidColor(palette.inkPrimary),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp)
                    .onFocusChanged { searchFocused = it.isFocused },
                decorationBox = { innerTextField ->
                    Row(
                        modifier = Modifier
                            .fillMaxSize()
                            .clip(searchShape)
                            .background(palette.surface)
                            .border(1.dp, searchBorder, searchShape)
                            .padding(start = 14.dp, end = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        SearchGlyph(tint = if (searchFocused) palette.inkPrimary else palette.inkMuted)
                        Spacer(Modifier.width(10.dp))
                        Box(
                            modifier = Modifier.weight(1f),
                            contentAlignment = Alignment.CenterStart,
                        ) {
                            if (query.isEmpty()) {
                                Text(
                                    text = "Search apps or package name",
                                    style = VdpiTextStyles.body,
                                    color = palette.inkMuted,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                            innerTextField()
                        }
                        if (query.isNotEmpty()) {
                            Box(
                                modifier = Modifier
                                    .size(44.dp)
                                    .clip(RoundedCornerShape(8.dp))
                                    .clickable(role = Role.Button) {
                                        query = ""
                                        focusManager.clearFocus()
                                    }
                                    .semantics { contentDescription = "Clear search" },
                                contentAlignment = Alignment.Center,
                            ) {
                                Text(
                                    text = "×",
                                    fontFamily = GeistMono,
                                    fontSize = 16.sp,
                                    color = palette.inkSecondary,
                                )
                            }
                        }
                    }
                },
            )

            Spacer(Modifier.height(10.dp))

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                FilterPill(
                    label = "All",
                    selected = activeFilter == AppFilter.ALL,
                    onClick = { activeFilter = AppFilter.ALL },
                )
                FilterPill(
                    label = "Selected (${settings.splitPackages.size})",
                    selected = activeFilter == AppFilter.SELECTED,
                    onClick = { activeFilter = AppFilter.SELECTED },
                )
                FilterPill(
                    label = if (showSystem) "System: On" else "System",
                    selected = showSystem,
                    onClick = { showSystem = !showSystem },
                )
                if (settings.splitPackages.isNotEmpty()) {
                    Box(
                        modifier = Modifier
                            .heightIn(min = 44.dp)
                            .clip(RoundedCornerShape(8.dp))
                            .clickable(role = Role.Button, onClick = onClearPackages)
                            .padding(horizontal = 12.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = "Reset",
                            style = VdpiTextStyles.monoSmall,
                            color = palette.danger,
                        )
                    }
                }
            }

            Spacer(Modifier.height(10.dp))
        }

        HairlineRule()

        if (loading && apps.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center,
            ) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    strokeWidth = 2.dp,
                    color = palette.inkSecondary,
                )
            }
        } else if (filtered.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = if (activeFilter == AppFilter.SELECTED) {
                        "No apps selected"
                    } else {
                        "No matching apps"
                    },
                    style = VdpiTextStyles.monoSmall,
                    fontSize = 12.sp,
                    color = palette.inkMuted,
                )
            }
        } else {
            // Full-bleed native list with crisp inset hairline dividers (no claustrophobic outer card)
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentPadding = PaddingValues(bottom = 16.dp),
            ) {
                itemsIndexed(filtered, key = { _, item -> item.packageName }) { idx, app ->
                    if (idx > 0) {
                        HairlineRule(modifier = Modifier.padding(start = 68.dp))
                    }
                    val selected = app.packageName in settings.splitPackages
                    AppRow(
                        item = app,
                        selected = selected,
                        onToggle = { onTogglePackage(app.packageName) },
                    )
                }
            }
        }
    }
}

@Composable
private fun FilterPill(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val shape = RoundedCornerShape(8.dp)
    Box(
        modifier = Modifier
            .heightIn(min = 44.dp)
            .clip(shape)
            .background(if (selected) palette.surfaceRaised else palette.surface)
            .border(1.dp, if (selected) palette.borderStrong else palette.border, shape)
            .clickable(role = Role.Tab, onClick = onClick)
            .padding(horizontal = 12.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = label,
            style = VdpiTextStyles.monoSmall,
            color = if (selected) palette.inkPrimary else palette.inkSecondary,
        )
    }
}

@Composable
private fun SearchGlyph(tint: Color) {
    Canvas(modifier = Modifier.size(15.dp)) {
        val stroke = 1.5.dp.toPx()
        val r = size.minDimension * 0.34f
        val center = Offset(size.width * 0.42f, size.height * 0.42f)
        drawCircle(
            color = tint,
            radius = r,
            center = center,
            style = Stroke(width = stroke),
        )
        drawLine(
            color = tint,
            start = Offset(center.x + r * 0.72f, center.y + r * 0.72f),
            end = Offset(size.width * 0.88f, size.height * 0.88f),
            strokeWidth = stroke,
            cap = StrokeCap.Round,
        )
    }
}

@Composable
private fun AppRow(
    item: InstalledAppItem,
    selected: Boolean,
    onToggle: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .toggleable(
                value = selected,
                role = Role.Switch,
                onValueChange = {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onToggle()
                },
            )
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        AppIconThumbnail(bitmap = item.icon)
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = item.label,
                style = VdpiTextStyles.rowTitle,
                color = palette.inkPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = item.packageName,
                style = VdpiTextStyles.monoSmall,
                color = palette.inkMuted,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Spacer(Modifier.width(12.dp))
        PrecisionSwitch(
            checked = selected,
            onCheckedChange = null,
            useSignalAccent = true,
        )
    }
}

@Composable
private fun AppIconThumbnail(bitmap: ImageBitmap?) {
    val palette = VdpiThemeTokens.palette
    val shape = RoundedCornerShape(9.dp)
    if (bitmap != null) {
        Image(
            bitmap = bitmap,
            contentDescription = null,
            modifier = Modifier
                .size(36.dp)
                .clip(shape),
        )
    } else {
        Box(
            modifier = Modifier
                .size(36.dp)
                .clip(shape)
                .background(palette.surfaceRaised)
                .border(1.dp, palette.border, shape),
        )
    }
}
