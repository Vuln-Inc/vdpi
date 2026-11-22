package com.vulninc.vdpi.ui.screens

import android.graphics.drawable.Drawable
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import com.vulninc.vdpi.data.SplitTunnelMode
import com.vulninc.vdpi.data.VdpiSettings
import com.vulninc.vdpi.ui.InstalledAppItem
import com.vulninc.vdpi.ui.components.HairlineRule
import com.vulninc.vdpi.ui.components.PrecisionSwitch
import com.vulninc.vdpi.ui.components.SegmentedControl
import com.vulninc.vdpi.ui.theme.GeistMono
import com.vulninc.vdpi.ui.theme.GeistSans
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens

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
    var query by remember { mutableStateOf("") }
    var showSystem by remember { mutableStateOf(false) }

    val filtered = remember(apps, query, showSystem, settings.splitPackages) {
        val q = query.trim().lowercase()
        apps.filter { app ->
            (showSystem || !app.isSystem || app.packageName in settings.splitPackages) &&
                (q.isEmpty() ||
                    app.label.lowercase().contains(q) ||
                    app.packageName.lowercase().contains(q))
        }.sortedWith(
            compareByDescending<InstalledAppItem> { it.packageName in settings.splitPackages }
                .thenBy { it.label.lowercase() }
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp),
    ) {
        Spacer(Modifier.height(16.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = "Split Tunnel",
                fontFamily = GeistSans,
                fontWeight = FontWeight.SemiBold,
                fontSize = 20.sp,
                letterSpacing = (-0.4).sp,
                color = palette.inkPrimary,
            )
            Text(
                text = "${settings.splitPackages.size} selected",
                fontFamily = GeistMono,
                fontSize = 11.sp,
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
            fontFamily = GeistSans,
            fontSize = 12.sp,
            lineHeight = 17.sp,
            color = palette.inkSecondary,
        )

        Spacer(Modifier.height(14.dp))

        // Minimal hairline search field
        val searchShape = RoundedCornerShape(10.dp)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(42.dp)
                .clip(searchShape)
                .background(palette.surface)
                .border(1.dp, palette.border, searchShape)
                .padding(horizontal = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(modifier = Modifier.weight(1f)) {
                if (query.isEmpty()) {
                    Text(
                        text = "Search apps or package name",
                        fontFamily = GeistSans,
                        fontSize = 13.sp,
                        color = palette.inkMuted,
                    )
                }
                BasicTextField(
                    value = query,
                    onValueChange = { query = it },
                    singleLine = true,
                    textStyle = TextStyle(
                        fontFamily = GeistSans,
                        fontSize = 13.sp,
                        color = palette.inkPrimary,
                    ),
                    cursorBrush = SolidColor(palette.inkPrimary),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            if (query.isNotEmpty()) {
                Text(
                    text = "Clear",
                    fontFamily = GeistMono,
                    fontSize = 11.sp,
                    color = palette.inkSecondary,
                    modifier = Modifier
                        .clickable { query = "" }
                        .padding(start = 8.dp),
                )
            }
        }

        Spacer(Modifier.height(10.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            val pillShape = RoundedCornerShape(8.dp)
            Text(
                text = if (showSystem) "Hide system apps" else "Show system apps",
                fontFamily = GeistMono,
                fontSize = 11.sp,
                color = if (showSystem) palette.inkPrimary else palette.inkSecondary,
                modifier = Modifier
                    .clip(pillShape)
                    .background(if (showSystem) palette.surfaceRaised else palette.surface)
                    .border(1.dp, palette.border, pillShape)
                    .clickable { showSystem = !showSystem }
                    .padding(horizontal = 10.dp, vertical = 6.dp),
            )

            if (settings.splitPackages.isNotEmpty()) {
                Text(
                    text = "Reset selection",
                    fontFamily = GeistMono,
                    fontSize = 11.sp,
                    color = palette.inkSecondary,
                    modifier = Modifier
                        .clip(pillShape)
                        .clickable(onClick = onClearPackages)
                        .padding(horizontal = 8.dp, vertical = 6.dp),
                )
            }
        }

        Spacer(Modifier.height(12.dp))

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
                    text = "No matching apps",
                    fontFamily = GeistMono,
                    fontSize = 12.sp,
                    color = palette.inkMuted,
                )
            }
        } else {
            val listShape = RoundedCornerShape(14.dp)
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .clip(listShape)
                    .background(palette.surface)
                    .border(1.dp, palette.border, listShape),
                contentPadding = PaddingValues(vertical = 4.dp),
            ) {
                itemsIndexed(filtered, key = { _, item -> item.packageName }) { idx, app ->
                    if (idx > 0) HairlineRule()
                    val selected = app.packageName in settings.splitPackages
                    AppRow(
                        item = app,
                        selected = selected,
                        onToggle = { onTogglePackage(app.packageName) },
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
        }
    }
}

@Composable
private fun AppRow(
    item: InstalledAppItem,
    selected: Boolean,
    onToggle: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onToggle)
            .padding(horizontal = 14.dp, vertical = 11.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        AppIconThumbnail(icon = item.icon)
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = item.label,
                fontFamily = GeistSans,
                fontWeight = FontWeight.Medium,
                fontSize = 14.sp,
                color = palette.inkPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = item.packageName,
                fontFamily = GeistMono,
                fontSize = 11.sp,
                color = palette.inkMuted,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Spacer(Modifier.width(10.dp))
        PrecisionSwitch(
            checked = selected,
            onCheckedChange = { onToggle() },
            useSignalAccent = true,
        )
    }
}

@Composable
private fun AppIconThumbnail(icon: Drawable?) {
    val palette = VdpiThemeTokens.palette
    val bitmap = remember(icon) {
        icon?.let { runCatching { it.toBitmap(72, 72).asImageBitmap() }.getOrNull() }
    }
    val shape = RoundedCornerShape(8.dp)
    if (bitmap != null) {
        Image(
            bitmap = bitmap,
            contentDescription = null,
            modifier = Modifier
                .size(34.dp)
                .clip(shape),
        )
    } else {
        Box(
            modifier = Modifier
                .size(34.dp)
                .clip(shape)
                .background(palette.surfaceRaised)
                .border(1.dp, palette.border, shape),
        )
    }
}
