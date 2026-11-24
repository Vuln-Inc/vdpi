package com.vulninc.vdpi.ui.screens

import android.content.res.Configuration
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
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
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vulninc.vdpi.data.SplitTunnelMode
import com.vulninc.vdpi.data.VdpiSettings
import com.vulninc.vdpi.ui.InstalledAppItem
import com.vulninc.vdpi.ui.components.FloatingGlassIconButton
import com.vulninc.vdpi.ui.components.GhostActionButton
import com.vulninc.vdpi.ui.components.HairlineRule
import com.vulninc.vdpi.ui.components.InsetGroupedCard
import com.vulninc.vdpi.ui.components.LocalBottomChromePadding
import com.vulninc.vdpi.ui.components.LocalTopOverlayPadding
import com.vulninc.vdpi.ui.components.PrecisionSwitch
import com.vulninc.vdpi.ui.components.SectionFooter
import com.vulninc.vdpi.ui.components.SegmentedControl
import com.vulninc.vdpi.ui.components.springPress
import com.vulninc.vdpi.ui.theme.VdpiTextStyles
import com.vulninc.vdpi.ui.theme.VdpiThemeTokens
import java.util.Locale
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

private enum class AppFilter {
    ALL,
    SELECTED,
}

// ── Screen ──

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
    val focusManager = LocalFocusManager.current
    val bottomChromePadding = LocalBottomChromePadding.current
    val topOverlayPadding = LocalTopOverlayPadding.current
    val configuration = LocalConfiguration.current
    val isLandscape = configuration.orientation == Configuration.ORIENTATION_LANDSCAPE &&
        configuration.screenWidthDp >= 560

    var query by rememberSaveable { mutableStateOf("") }
    var showSystem by rememberSaveable { mutableStateOf(false) }
    var activeFilter by rememberSaveable { mutableStateOf(AppFilter.ALL) }

    val selectedCount = settings.splitPackages.size

    // Stable alphabetical order during interaction so toggling never shifts a row under the thumb.
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

    val onClearSearch = {
        query = ""
        focusManager.clearFocus()
    }
    val onSearch = { focusManager.clearFocus() }

    Box(
        modifier = modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal)),
        contentAlignment = Alignment.TopCenter,
    ) {
        Column(
            modifier = (if (isLandscape) Modifier.widthIn(max = 760.dp) else Modifier)
                .fillMaxSize(),
        ) {
            Spacer(Modifier.height(topOverlayPadding))

            AppsHeader(
                isLandscape = isLandscape,
                splitTunnelMode = settings.splitTunnelMode,
                selectedCount = selectedCount,
                query = query,
                activeFilter = activeFilter,
                showSystem = showSystem,
                onSetSplitMode = onSetSplitMode,
                onClearPackages = onClearPackages,
                onQueryChange = { query = it },
                onSearch = onSearch,
                onClearSearch = onClearSearch,
                onSelectFilter = { activeFilter = it },
                onToggleSystem = { showSystem = !showSystem },
            )

            when {
                loading && apps.isEmpty() -> AppsLoadingState(
                    bottomPadding = bottomChromePadding,
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                )
                filtered.isEmpty() -> AppsEmptyState(
                    activeFilter = activeFilter,
                    query = query,
                    bottomPadding = bottomChromePadding,
                    onClearSearch = onClearSearch,
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                )
                else -> AppsList(
                    apps = filtered,
                    selectedPackages = settings.splitPackages,
                    bottomPadding = bottomChromePadding,
                    onTogglePackage = onTogglePackage,
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                )
            }
        }
    }
}

// ── Header & Filters ──

@Composable
private fun AppsHeader(
    isLandscape: Boolean,
    splitTunnelMode: SplitTunnelMode,
    selectedCount: Int,
    query: String,
    activeFilter: AppFilter,
    showSystem: Boolean,
    onSetSplitMode: (SplitTunnelMode) -> Unit,
    onClearPackages: () -> Unit,
    onQueryChange: (String) -> Unit,
    onSearch: () -> Unit,
    onClearSearch: () -> Unit,
    onSelectFilter: (AppFilter) -> Unit,
    onToggleSystem: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    val resetButton: @Composable () -> Unit = {
        AppsResetButton(
            visible = selectedCount > 0,
            onClick = onClearPackages,
        )
    }
    val modeControl: @Composable (Modifier) -> Unit = { slotModifier ->
        AppsModeSegmentedControl(
            selected = splitTunnelMode,
            onSelect = onSetSplitMode,
            modifier = slotModifier,
        )
    }
    val searchField: @Composable (Modifier) -> Unit = { slotModifier ->
        AppleSearchField(
            query = query,
            onQueryChange = onQueryChange,
            onSearch = onSearch,
            onClear = onClearSearch,
            modifier = slotModifier,
        )
    }
    val filterChips: @Composable (Modifier) -> Unit = { slotModifier ->
        AppsFilterChipRow(
            activeFilter = activeFilter,
            selectedCount = selectedCount,
            showSystem = showSystem,
            onSelectFilter = onSelectFilter,
            onToggleSystem = onToggleSystem,
            modifier = slotModifier,
        )
    }

    Column(modifier = Modifier.padding(horizontal = 16.dp)) {
        if (isLandscape) {
            // Compact landscape header: title left, reset + segmented mode picker right
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 6.dp, bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    text = "Apps",
                    style = VdpiTextStyles.pageTitle.copy(
                        fontSize = 24.sp,
                        lineHeight = 28.sp,
                        letterSpacing = (-0.3).sp,
                    ),
                    color = palette.inkPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                resetButton()
                modeControl(Modifier.widthIn(max = 320.dp))
            }

            // Combined landscape search bar + tonal filter chips row
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                searchField(Modifier.weight(1f))
                filterChips(Modifier)
            }
        } else {
            Spacer(Modifier.height(12.dp))

            // Apple Large Title header with conditional monochrome FloatingGlassIconButton
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 44.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = "Apps",
                    style = VdpiTextStyles.pageTitle,
                    color = palette.inkPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                resetButton()
            }

            Spacer(Modifier.height(12.dp))
            modeControl(Modifier)

            // 1-line SectionFooter-style muted explanation
            AnimatedContent(
                targetState = splitTunnelMode,
                transitionSpec = { fadeIn(tween(160)) togetherWith fadeOut(tween(120)) },
                label = "splitModeSummary",
            ) { mode ->
                SectionFooter(
                    text = when (mode) {
                        SplitTunnelMode.BYPASS_SELECTED ->
                            "Selected apps connect directly without DPI bypass."
                        SplitTunnelMode.ONLY_SELECTED ->
                            "Only selected apps route through vdpi."
                    },
                )
            }

            Spacer(Modifier.height(16.dp))
            searchField(Modifier)
            Spacer(Modifier.height(6.dp))
            filterChips(Modifier.fillMaxWidth())
        }

        Spacer(Modifier.height(6.dp))
    }
}

@Composable
private fun AppsResetButton(
    visible: Boolean,
    onClick: () -> Unit,
) {
    val palette = VdpiThemeTokens.palette
    AnimatedVisibility(
        visible = visible,
        enter = fadeIn(tween(180)) + scaleIn(initialScale = 0.84f, animationSpec = tween(180)),
        exit = fadeOut(tween(140)) + scaleOut(targetScale = 0.84f, animationSpec = tween(140)),
    ) {
        FloatingGlassIconButton(
            onClick = onClick,
            contentDescription = "Reset selected apps",
            size = 42.dp,
        ) {
            ResetSelectionGlyph(tint = palette.inkPrimary)
        }
    }
}

@Composable
private fun AppsModeSegmentedControl(
    selected: SplitTunnelMode,
    onSelect: (SplitTunnelMode) -> Unit,
    modifier: Modifier = Modifier,
) {
    SegmentedControl(
        options = SplitTunnelMode.entries,
        selected = selected,
        labelFor = { mode ->
            when (mode) {
                SplitTunnelMode.BYPASS_SELECTED -> "Bypass Selected"
                SplitTunnelMode.ONLY_SELECTED -> "Only Selected"
            }
        },
        onSelect = onSelect,
        modifier = modifier,
    )
}

@Composable
private fun AppsFilterChipRow(
    activeFilter: AppFilter,
    selectedCount: Int,
    showSystem: Boolean,
    onSelectFilter: (AppFilter) -> Unit,
    onToggleSystem: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier.horizontalScroll(rememberScrollState()),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        TonalFilterChip(
            label = "All",
            selected = activeFilter == AppFilter.ALL,
            onClick = { onSelectFilter(AppFilter.ALL) },
        )
        TonalFilterChip(
            label = if (selectedCount > 0) "Selected ($selectedCount)" else "Selected",
            selected = activeFilter == AppFilter.SELECTED,
            onClick = { onSelectFilter(AppFilter.SELECTED) },
        )
        TonalFilterChip(
            label = "System",
            selected = showSystem,
            onClick = onToggleSystem,
            isToggle = true,
        )
    }
}

@Composable
private fun ResetSelectionGlyph(tint: Color) {
    Canvas(modifier = Modifier.size(18.dp)) {
        val stroke = 1.75.dp.toPx()
        val cx = size.width * 0.5f
        val cy = size.height * 0.52f
        val r = size.minDimension * 0.33f
        val startAngleDeg = -140f

        drawArc(
            color = tint,
            startAngle = startAngleDeg,
            sweepAngle = 300f,
            useCenter = false,
            topLeft = Offset(cx - r, cy - r),
            size = Size(r * 2f, r * 2f),
            style = Stroke(width = stroke, cap = StrokeCap.Round),
        )

        val rad = startAngleDeg * (PI / 180.0)
        val tipX = cx + (r * cos(rad)).toFloat()
        val tipY = cy + (r * sin(rad)).toFloat()
        val leg = size.minDimension * 0.19f

        val arrow = Path().apply {
            moveTo(tipX + leg, tipY + leg * 0.08f)
            lineTo(tipX, tipY)
            lineTo(tipX + leg * 0.08f, tipY - leg)
        }
        drawPath(
            path = arrow,
            color = tint,
            style = Stroke(
                width = stroke,
                cap = StrokeCap.Round,
                join = StrokeJoin.Round,
            ),
        )
    }
}

// ── App Rows & Empty States ──

private val SingleRowShape = RoundedCornerShape(16.dp)
private val FirstRowShape = RoundedCornerShape(topStart = 16.dp, topEnd = 16.dp)
private val LastRowShape = RoundedCornerShape(bottomStart = 16.dp, bottomEnd = 16.dp)

@Composable
private fun AppsList(
    apps: List<InstalledAppItem>,
    selectedPackages: Set<String>,
    bottomPadding: Dp,
    onTogglePackage: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val lastIndex = apps.lastIndex
    LazyColumn(
        modifier = modifier,
        contentPadding = PaddingValues(
            start = 16.dp,
            end = 16.dp,
            top = 4.dp,
            bottom = bottomPadding,
        ),
        verticalArrangement = Arrangement.spacedBy(0.dp),
    ) {
        itemsIndexed(
            items = apps,
            key = { _, app -> app.packageName },
        ) { index, app ->
            val rowShape = when {
                lastIndex == 0 -> SingleRowShape
                index == 0 -> FirstRowShape
                index == lastIndex -> LastRowShape
                else -> RectangleShape
            }
            GroupedAppRow(
                item = app,
                selected = app.packageName in selectedPackages,
                shape = rowShape,
                showDivider = index < lastIndex,
                onToggle = { onTogglePackage(app.packageName) },
                modifier = Modifier.animateItem(),
            )
        }
    }
}

@Composable
private fun AppsLoadingState(
    bottomPadding: Dp,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    AppsStatusCard(
        bottomPadding = bottomPadding,
        verticalSpacing = 12.dp,
        modifier = modifier,
    ) {
        CircularProgressIndicator(
            modifier = Modifier.size(22.dp),
            strokeWidth = 2.dp,
            color = palette.inkSecondary,
        )
        Text(
            text = "Loading installed apps",
            style = VdpiTextStyles.body,
            color = palette.inkSecondary,
        )
    }
}

@Composable
private fun AppsEmptyState(
    activeFilter: AppFilter,
    query: String,
    bottomPadding: Dp,
    onClearSearch: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    AppsStatusCard(
        bottomPadding = bottomPadding,
        verticalSpacing = 6.dp,
        modifier = modifier,
    ) {
        Text(
            text = when {
                activeFilter == AppFilter.SELECTED -> "No Apps Selected"
                query.isNotBlank() -> "No Matching Apps"
                else -> "No Apps Available"
            },
            style = VdpiTextStyles.rowTitle.copy(fontWeight = FontWeight.Medium),
            color = palette.inkPrimary,
            textAlign = TextAlign.Center,
        )
        Text(
            text = when {
                activeFilter == AppFilter.SELECTED ->
                    "Switch to All and toggle any app to include it."
                query.isNotBlank() ->
                    "Try another app name or package identifier."
                else ->
                    "Enable System to inspect system packages."
            },
            style = VdpiTextStyles.caption,
            color = palette.inkSecondary,
            textAlign = TextAlign.Center,
        )
        if (query.isNotBlank()) {
            Spacer(Modifier.height(6.dp))
            GhostActionButton(
                label = "Clear Search",
                onClick = onClearSearch,
            )
        }
    }
}

@Composable
private fun AppsStatusCard(
    bottomPadding: Dp,
    verticalSpacing: Dp,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    Box(
        modifier = modifier
            .padding(horizontal = 16.dp)
            .padding(top = 4.dp, bottom = bottomPadding),
        contentAlignment = Alignment.TopCenter,
    ) {
        InsetGroupedCard(
            modifier = Modifier.fillMaxWidth(),
            radius = 16.dp,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp, vertical = 28.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(verticalSpacing),
                content = content,
            )
        }
    }
}

@Composable
private fun GroupedAppRow(
    item: InstalledAppItem,
    selected: Boolean,
    shape: Shape,
    showDivider: Boolean,
    onToggle: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val interaction = remember { MutableInteractionSource() }
    val isPressed by interaction.collectIsPressedAsState()

    val pressWash by animateColorAsState(
        targetValue = if (isPressed) {
            palette.inkPrimary.copy(alpha = 0.06f)
        } else {
            Color.Transparent
        },
        animationSpec = tween(durationMillis = if (isPressed) 60 else 160),
        label = "appRowPressWash",
    )

    val subtitle = if (item.isSystem) {
        "${item.packageName} \u00B7 System"
    } else {
        item.packageName
    }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(shape)
            .background(palette.surface),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 56.dp)
                .background(pressWash)
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
                .padding(horizontal = 16.dp, vertical = 10.dp),
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
                Spacer(Modifier.height(2.dp))
                Text(
                    text = subtitle,
                    style = VdpiTextStyles.caption.copy(
                        fontSize = 12.sp,
                        lineHeight = 16.sp,
                    ),
                    color = palette.inkSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Spacer(Modifier.width(12.dp))
            PrecisionSwitch(
                checked = selected,
                onCheckedChange = null,
            )
        }

        if (showDivider) {
            HairlineRule(startIndent = 64.dp)
        }
    }
}

@Composable
private fun AppIconThumbnail(bitmap: ImageBitmap?) {
    val palette = VdpiThemeTokens.palette
    val shape = RoundedCornerShape(8.dp)
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
                .background(palette.surfaceRaised),
            contentAlignment = Alignment.Center,
        ) {
            Canvas(modifier = Modifier.size(16.dp)) {
                val stroke = 1.5.dp.toPx()
                val inset = stroke * 0.5f
                drawRoundRect(
                    color = palette.inkMuted,
                    topLeft = Offset(inset, inset),
                    size = Size(size.width - stroke, size.height - stroke),
                    cornerRadius = CornerRadius(3.5.dp.toPx(), 3.5.dp.toPx()),
                    style = Stroke(width = stroke),
                )
            }
        }
    }
}

// ── Search Field & Chips ──

@Composable
private fun AppleSearchField(
    query: String,
    onQueryChange: (String) -> Unit,
    onSearch: () -> Unit,
    onClear: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val shape = RoundedCornerShape(12.dp)

    BasicTextField(
        value = query,
        onValueChange = onQueryChange,
        singleLine = true,
        keyboardOptions = KeyboardOptions(
            autoCorrectEnabled = false,
            imeAction = ImeAction.Search,
        ),
        keyboardActions = KeyboardActions(
            onSearch = { onSearch() },
        ),
        textStyle = VdpiTextStyles.body.copy(color = palette.inkPrimary),
        cursorBrush = SolidColor(palette.accent),
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = 44.dp),
        decorationBox = { innerTextField ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 44.dp)
                    .clip(shape)
                    .background(palette.surfaceRaised)
                    .padding(start = 12.dp, end = if (query.isNotEmpty()) 2.dp else 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                SearchGlyph(tint = palette.inkSecondary)
                Spacer(Modifier.width(8.dp))
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .padding(vertical = 8.dp),
                    contentAlignment = Alignment.CenterStart,
                ) {
                    if (query.isEmpty()) {
                        Text(
                            text = "Search apps",
                            style = VdpiTextStyles.body,
                            color = palette.inkSecondary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    innerTextField()
                }
                AnimatedVisibility(
                    visible = query.isNotEmpty(),
                    enter = fadeIn(tween(140)) + scaleIn(initialScale = 0.80f, animationSpec = tween(140)),
                    exit = fadeOut(tween(110)) + scaleOut(targetScale = 0.80f, animationSpec = tween(110)),
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
                                onClear()
                            }
                            .semantics { contentDescription = "Clear search" },
                        contentAlignment = Alignment.Center,
                    ) {
                        ClearFieldGlyph(
                            circleColor = palette.inkMuted,
                            crossColor = palette.surfaceRaised,
                        )
                    }
                }
            }
        },
    )
}

@Composable
private fun TonalFilterChip(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
    isToggle: Boolean = false,
) {
    val palette = VdpiThemeTokens.palette
    val haptic = LocalHapticFeedback.current
    val interaction = remember { MutableInteractionSource() }

    val fillColor by animateColorAsState(
        targetValue = if (selected) palette.primaryButtonBg else palette.surfaceRaised,
        animationSpec = tween(150),
        label = "filterChipFill",
    )
    val textColor by animateColorAsState(
        targetValue = if (selected) palette.primaryButtonInk else palette.inkSecondary,
        animationSpec = tween(150),
        label = "filterChipText",
    )

    val selectionModifier = if (isToggle) {
        Modifier.toggleable(
            value = selected,
            interactionSource = interaction,
            indication = null,
            role = Role.Checkbox,
            onValueChange = {
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                onClick()
            },
        )
    } else {
        Modifier.selectable(
            selected = selected,
            interactionSource = interaction,
            indication = null,
            role = Role.Tab,
            onClick = {
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                onClick()
            },
        )
    }

    Box(
        modifier = Modifier
            .heightIn(min = 44.dp)
            .widthIn(min = 44.dp)
            .then(selectionModifier),
        contentAlignment = Alignment.Center,
    ) {
        Box(
            modifier = Modifier
                .springPress(interactionSource = interaction, pressedScale = 0.95f)
                .clip(CircleShape)
                .background(fillColor)
                .padding(horizontal = 14.dp, vertical = 7.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = label,
                style = VdpiTextStyles.caption.copy(
                    fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium,
                    lineHeight = 16.sp,
                    fontFeatureSettings = "tnum",
                ),
                color = textColor,
                maxLines = 1,
            )
        }
    }
}

@Composable
private fun SearchGlyph(tint: Color) {
    Canvas(modifier = Modifier.size(18.dp)) {
        val stroke = 1.65.dp.toPx()
        val r = size.minDimension * 0.31f
        val center = Offset(size.width * 0.43f, size.height * 0.43f)
        drawCircle(
            color = tint,
            radius = r,
            center = center,
            style = Stroke(width = stroke),
        )
        drawLine(
            color = tint,
            start = Offset(center.x + r * 0.72f, center.y + r * 0.72f),
            end = Offset(size.width * 0.86f, size.height * 0.86f),
            strokeWidth = stroke,
            cap = StrokeCap.Round,
        )
    }
}

@Composable
private fun ClearFieldGlyph(
    circleColor: Color,
    crossColor: Color,
) {
    Canvas(modifier = Modifier.size(18.dp)) {
        val stroke = 1.6.dp.toPx()
        val w = size.width
        val h = size.height
        drawCircle(color = circleColor)
        drawLine(
            color = crossColor,
            start = Offset(w * 0.34f, h * 0.34f),
            end = Offset(w * 0.66f, h * 0.66f),
            strokeWidth = stroke,
            cap = StrokeCap.Round,
        )
        drawLine(
            color = crossColor,
            start = Offset(w * 0.66f, h * 0.34f),
            end = Offset(w * 0.34f, h * 0.66f),
            strokeWidth = stroke,
            cap = StrokeCap.Round,
        )
    }
}
