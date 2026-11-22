package com.vulninc.vdpi.ui.screens

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.interaction.MutableInteractionSource
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
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
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
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vulninc.vdpi.data.SplitTunnelMode
import com.vulninc.vdpi.data.VdpiSettings
import com.vulninc.vdpi.ui.InstalledAppItem
import com.vulninc.vdpi.ui.components.FloatingGlassIconButton
import com.vulninc.vdpi.ui.components.GhostActionButton
import com.vulninc.vdpi.ui.components.LiquidGlassCapsule
import com.vulninc.vdpi.ui.components.LiquidGlassCard
import com.vulninc.vdpi.ui.components.LocalBottomChromePadding
import com.vulninc.vdpi.ui.components.LocalTopOverlayPadding
import com.vulninc.vdpi.ui.components.PrecisionSwitch
import com.vulninc.vdpi.ui.components.SegmentedControl
import com.vulninc.vdpi.ui.components.VdpiMotion
import com.vulninc.vdpi.ui.components.springPress
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
    val haptic = LocalHapticFeedback.current
    val bottomChromePadding = LocalBottomChromePadding.current
    val topOverlayPadding by animateDpAsState(
        targetValue = LocalTopOverlayPadding.current,
        animationSpec = VdpiMotion.tabLensSpring,
        label = "appsTopOverlay",
    )

    var query by rememberSaveable { mutableStateOf("") }
    var showSystem by rememberSaveable { mutableStateOf(false) }
    var activeFilter by rememberSaveable { mutableStateOf(AppFilter.ALL) }
    var searchFocused by remember { mutableStateOf(false) }

    val selectedCount = settings.splitPackages.size

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

    val searchFocusProgress by animateFloatAsState(
        targetValue = if (searchFocused) 1f else 0f,
        animationSpec = tween(180),
        label = "searchFocusProgress",
    )
    val searchRimTint = if (searchFocusProgress > 0.01f) {
        lerp(palette.glassRimTop, palette.accent, searchFocusProgress)
    } else {
        null
    }
    val searchFillTint by animateColorAsState(
        targetValue = if (searchFocused) palette.glassFillElevated else palette.glassFill,
        animationSpec = tween(180),
        label = "searchFill",
    )
    val searchGlyphTint by animateColorAsState(
        targetValue = if (searchFocused) palette.accent else palette.inkMuted,
        animationSpec = tween(180),
        label = "searchGlyph",
    )

    Column(
        modifier = modifier
            .fillMaxSize()
            .statusBarsPadding(),
    ) {
        Spacer(Modifier.height(topOverlayPadding))

        Column(modifier = Modifier.padding(horizontal = 20.dp)) {
            Spacer(Modifier.height(14.dp))

            // Liquid Glass editorial header
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Split Tunnel",
                        style = VdpiTextStyles.pageTitle,
                        color = palette.inkPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Spacer(Modifier.height(6.dp))
                    LiquidGlassCapsule(
                        rimTint = if (selectedCount > 0) palette.accent else null,
                        fillTint = if (selectedCount > 0) palette.accentTint else palette.glassFillSubtle,
                        elevated = false,
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .clip(CircleShape)
                                    .background(if (selectedCount > 0) palette.accent else palette.inkMuted),
                            )
                            Text(
                                text = "$selectedCount selected",
                                style = VdpiTextStyles.monoSmall,
                                color = if (selectedCount > 0) palette.inkPrimary else palette.inkSecondary,
                            )
                        }
                    }
                }

                AnimatedVisibility(
                    visible = selectedCount > 0,
                    enter = fadeIn(tween(180)) + scaleIn(initialScale = 0.82f, animationSpec = tween(180)),
                    exit = fadeOut(tween(140)) + scaleOut(targetScale = 0.82f, animationSpec = tween(140)),
                ) {
                    FloatingGlassIconButton(
                        onClick = onClearPackages,
                        contentDescription = "Clear selected apps",
                        size = 44.dp,
                    ) {
                        ClearSelectionGlyph(tint = palette.danger)
                    }
                }
            }

            Spacer(Modifier.height(16.dp))

            // Mode picker: sliding-lens Liquid Glass SegmentedControl
            SegmentedControl(
                options = SplitTunnelMode.entries,
                selected = settings.splitTunnelMode,
                labelFor = { it.label },
                onSelect = onSetSplitMode,
            )

            Spacer(Modifier.height(8.dp))

            AnimatedContent(
                targetState = settings.splitTunnelMode,
                transitionSpec = { fadeIn(tween(160)) togetherWith fadeOut(tween(120)) },
                label = "splitModeSummary",
            ) { mode ->
                Text(
                    text = when (mode) {
                        SplitTunnelMode.BYPASS_SELECTED ->
                            "Selected apps bypass vdpi directly (useful for local banking or LAN tools)."
                        SplitTunnelMode.ONLY_SELECTED ->
                            "Only selected apps route through vdpi. If none are selected, all apps stay protected."
                    },
                    style = VdpiTextStyles.caption,
                    color = palette.inkSecondary,
                )
            }

            Spacer(Modifier.height(14.dp))

            // 48.dp LiquidGlassCapsule search field with smooth accent focus rim glow
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
                    fontSize = 14.sp,
                    color = palette.inkPrimary,
                ),
                cursorBrush = SolidColor(palette.accent),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp)
                    .onFocusChanged { searchFocused = it.isFocused },
                decorationBox = { innerTextField ->
                    LiquidGlassCapsule(
                        modifier = Modifier.fillMaxSize(),
                        rimTint = searchRimTint,
                        fillTint = searchFillTint,
                        elevated = searchFocused,
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(start = 16.dp, end = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            SearchGlyph(tint = searchGlyphTint)
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
                            AnimatedVisibility(
                                visible = query.isNotEmpty(),
                                enter = fadeIn(tween(140)) + scaleIn(initialScale = 0.78f, animationSpec = tween(140)),
                                exit = fadeOut(tween(110)) + scaleOut(targetScale = 0.78f, animationSpec = tween(110)),
                            ) {
                                val clearInteraction = remember { MutableInteractionSource() }
                                Box(
                                    modifier = Modifier
                                        .size(44.dp)
                                        .springPress(
                                            interactionSource = clearInteraction,
                                            pressedScale = 0.88f,
                                        )
                                        .clip(CircleShape)
                                        .clickable(
                                            interactionSource = clearInteraction,
                                            indication = null,
                                            role = Role.Button,
                                        ) {
                                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                            query = ""
                                            focusManager.clearFocus()
                                        }
                                        .semantics { contentDescription = "Clear search" },
                                    contentAlignment = Alignment.Center,
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(24.dp)
                                            .clip(CircleShape)
                                            .background(palette.surfaceRaised),
                                        contentAlignment = Alignment.Center,
                                    ) {
                                        Text(
                                            text = "×",
                                            fontFamily = GeistMono,
                                            fontWeight = FontWeight.Medium,
                                            fontSize = 14.sp,
                                            color = palette.inkSecondary,
                                        )
                                    }
                                }
                            }
                        }
                    }
                },
            )

            Spacer(Modifier.height(10.dp))

            // Horizontal LiquidGlassCapsule filter chips
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                GlassFilterChip(
                    label = "All",
                    selected = activeFilter == AppFilter.ALL,
                    onClick = { activeFilter = AppFilter.ALL },
                )
                GlassFilterChip(
                    label = "Selected ($selectedCount)",
                    selected = activeFilter == AppFilter.SELECTED,
                    onClick = { activeFilter = AppFilter.SELECTED },
                )
                GlassFilterChip(
                    label = "System",
                    selected = showSystem,
                    onClick = { showSystem = !showSystem },
                )
            }

            Spacer(Modifier.height(10.dp))
        }

        if (loading && apps.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .padding(horizontal = 20.dp)
                    .padding(bottom = bottomChromePadding),
                contentAlignment = Alignment.Center,
            ) {
                LiquidGlassCard(
                    modifier = Modifier.fillMaxWidth(),
                    radius = 22.dp,
                    elevated = false,
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 24.dp, vertical = 28.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(24.dp),
                            strokeWidth = 2.dp,
                            color = palette.accent,
                        )
                        Text(
                            text = "Scanning installed apps",
                            style = VdpiTextStyles.body,
                            color = palette.inkSecondary,
                        )
                    }
                }
            }
        } else if (filtered.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .padding(horizontal = 20.dp)
                    .padding(bottom = bottomChromePadding),
                contentAlignment = Alignment.Center,
            ) {
                LiquidGlassCard(
                    modifier = Modifier.fillMaxWidth(),
                    radius = 22.dp,
                    elevated = false,
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 24.dp, vertical = 28.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(
                            text = when {
                                activeFilter == AppFilter.SELECTED -> "No apps selected"
                                query.isNotBlank() -> "No matching apps"
                                else -> "No apps available"
                            },
                            style = VdpiTextStyles.rowTitle,
                            color = palette.inkPrimary,
                            textAlign = TextAlign.Center,
                        )
                        Text(
                            text = when {
                                activeFilter == AppFilter.SELECTED ->
                                    "Switch to All and toggle any app to include it in this rule."
                                query.isNotBlank() ->
                                    "Try searching by another app name or package identifier."
                                else ->
                                    "Enable the System filter to inspect system packages."
                            },
                            style = VdpiTextStyles.caption,
                            color = palette.inkSecondary,
                            textAlign = TextAlign.Center,
                        )
                        if (query.isNotBlank()) {
                            Spacer(Modifier.height(4.dp))
                            GhostActionButton(
                                label = "Clear search",
                                onClick = {
                                    query = ""
                                    focusManager.clearFocus()
                                },
                            )
                        }
                    }
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentPadding = PaddingValues(
                    start = 16.dp,
                    end = 16.dp,
                    top = 4.dp,
                    bottom = bottomChromePadding,
                ),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(
                    items = filtered,
                    key = { it.packageName },
                ) { app ->
                    val selected = app.packageName in settings.splitPackages
                    AppRow(
                        item = app,
                        selected = selected,
                        onToggle = { onTogglePackage(app.packageName) },
                        modifier = Modifier.animateItem(),
                    )
                }
            }
        }
    }
}

@Composable
private fun GlassFilterChip(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val interaction = remember { MutableInteractionSource() }

    val fillColor by animateColorAsState(
        targetValue = if (selected) palette.accentTint else palette.glassFillSubtle,
        animationSpec = tween(160),
        label = "chipFill",
    )
    val textColor by animateColorAsState(
        targetValue = if (selected) palette.inkPrimary else palette.inkSecondary,
        animationSpec = tween(160),
        label = "chipText",
    )

    LiquidGlassCapsule(
        modifier = Modifier
            .heightIn(min = 44.dp)
            .springPress(interactionSource = interaction, pressedScale = 0.94f)
            .clip(CircleShape)
            .clickable(
                interactionSource = interaction,
                indication = null,
                role = Role.Tab,
            ) {
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                onClick()
            },
        rimTint = if (selected) palette.accent else null,
        fillTint = fillColor,
        elevated = selected,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            if (selected) {
                Box(
                    modifier = Modifier
                        .size(6.dp)
                        .clip(CircleShape)
                        .background(palette.accent),
                )
            }
            Text(
                text = label,
                style = VdpiTextStyles.monoSmall,
                fontWeight = if (selected) FontWeight.Medium else FontWeight.Normal,
                color = textColor,
            )
        }
    }
}

@Composable
private fun SearchGlyph(tint: Color) {
    Canvas(modifier = Modifier.size(16.dp)) {
        val stroke = 1.6.dp.toPx()
        val r = size.minDimension * 0.33f
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
private fun ClearSelectionGlyph(tint: Color) {
    Canvas(modifier = Modifier.size(18.dp)) {
        val stroke = 1.7.dp.toPx()
        val w = size.width
        val h = size.height
        drawLine(
            color = tint,
            start = Offset(w * 0.26f, h * 0.26f),
            end = Offset(w * 0.74f, h * 0.74f),
            strokeWidth = stroke,
            cap = StrokeCap.Round,
        )
        drawLine(
            color = tint,
            start = Offset(w * 0.74f, h * 0.26f),
            end = Offset(w * 0.26f, h * 0.74f),
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
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val interaction = remember { MutableInteractionSource() }
    val rowShape = RoundedCornerShape(16.dp)

    val rowBg by animateColorAsState(
        targetValue = if (selected) palette.signalTint else palette.glassFillSubtle,
        animationSpec = tween(160),
        label = "appRowBg",
    )
    val rowBorder by animateColorAsState(
        targetValue = if (selected) palette.signalBorder else palette.border,
        animationSpec = tween(160),
        label = "appRowBorder",
    )

    Row(
        modifier = modifier
            .fillMaxWidth()
            .springPress(interactionSource = interaction, pressedScale = 0.985f)
            .clip(rowShape)
            .background(rowBg)
            .border(1.dp, rowBorder, rowShape)
            .toggleable(
                value = selected,
                interactionSource = interaction,
                indication = null,
                role = Role.Switch,
                onValueChange = {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onToggle()
                },
            )
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        AppIconThumbnail(bitmap = item.icon)
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(
                    text = item.label,
                    style = VdpiTextStyles.rowTitle,
                    color = palette.inkPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false),
                )
                if (item.isSystem) {
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(4.dp))
                            .background(palette.surfaceRaised)
                            .border(0.5.dp, palette.border, RoundedCornerShape(4.dp))
                            .padding(horizontal = 5.dp, vertical = 1.dp),
                    ) {
                        Text(
                            text = "SYS",
                            style = VdpiTextStyles.monoSmall,
                            fontSize = 9.sp,
                            color = palette.inkMuted,
                        )
                    }
                }
            }
            Spacer(Modifier.height(1.dp))
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
    val shape = RoundedCornerShape(11.dp)
    if (bitmap != null) {
        Image(
            bitmap = bitmap,
            contentDescription = null,
            modifier = Modifier
                .size(40.dp)
                .clip(shape)
                .border(0.75.dp, palette.border, shape),
        )
    } else {
        Box(
            modifier = Modifier
                .size(40.dp)
                .clip(shape)
                .background(palette.surfaceRaised)
                .border(1.dp, palette.border, shape),
        )
    }
}
