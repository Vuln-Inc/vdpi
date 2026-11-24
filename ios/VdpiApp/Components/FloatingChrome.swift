import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

// MARK: - Tab Destination

enum VdpiTab: String, CaseIterable, Identifiable {
    case tunnel
    case settings

    var id: String { rawValue }

    var title: String {
        switch self {
        case .tunnel: return "Tunnel"
        case .settings: return "Settings"
        }
    }

    var systemImage: String {
        systemImage(selected: true)
    }

    func systemImage(selected: Bool) -> String {
        switch self {
        case .tunnel: return selected ? "shield.fill" : "shield"
        case .settings: return selected ? "gearshape.fill" : "gearshape"
        }
    }
}

// MARK: - Top-Floating "Settings Changed" Liquid Glass Popup

struct TopReconnectPopup: View {
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.colorSchemeContrast) private var colorSchemeContrast

    let pendingChangeSummary: String
    let isReloading: Bool
    let isCompactHeight: Bool
    let onReconnect: () -> Void
    let onDismiss: () -> Void

    @State private var popupDragOffset: CGFloat = 0

    init(
        pendingChangeSummary: String,
        isReloading: Bool,
        isCompactHeight: Bool,
        onReconnect: @escaping () -> Void,
        onDismiss: @escaping () -> Void
    ) {
        self.pendingChangeSummary = pendingChangeSummary
        self.isReloading = isReloading
        self.isCompactHeight = isCompactHeight
        self.onReconnect = onReconnect
        self.onDismiss = onDismiss
    }

    private var popupAnimation: Animation {
        reduceMotion ? .easeInOut(duration: 0.15) : .spring(response: 0.36, dampingFraction: 0.82)
    }

    private var dismissAnimation: Animation {
        reduceMotion ? .easeInOut(duration: 0.15) : VdpiMotion.dismiss
    }

    var body: some View {
        let subtitle: String = pendingChangeSummary.isEmpty
            ? "Reconnect to apply"
            : "Reconnect to apply · \(pendingChangeSummary)"

        HStack(spacing: 10) {
            Group {
                if isReloading && !reduceMotion {
                    ProgressView()
                        .progressViewStyle(.circular)
                        .controlSize(.mini)
                        .tint(palette.warning)
                        .frame(width: 14, height: 14)
                } else {
                    Circle()
                        .fill(palette.warning)
                        .frame(width: 8, height: 8)
                }
            }
            .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                Text("Settings Changed")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(palette.inkPrimary)
                    .lineLimit(1)

                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(palette.inkSecondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            HStack(spacing: 2) {
                Button {
                    VdpiHaptics.trigger(.medium)
                    onReconnect()
                } label: {
                    ZStack {
                        Text("Reconnect")
                            .font(.footnote.weight(.semibold))
                            .lineLimit(1)
                            .opacity(isReloading ? 0 : 1)

                        if isReloading {
                            ProgressView()
                                .progressViewStyle(.circular)
                                .controlSize(.mini)
                                .tint(.white)
                        }
                    }
                    .foregroundStyle(palette.primaryButtonInk)
                    .padding(.horizontal, 14)
                    .frame(minHeight: 34)
                    .background(Capsule().fill(palette.primaryButtonBg))
                    .overlay {
                        if colorSchemeContrast == .increased {
                            Capsule()
                                .strokeBorder(Color.white.opacity(0.45), lineWidth: 1.0)
                                .allowsHitTesting(false)
                        }
                    }
                    .frame(minHeight: 44)
                    .contentShape(Rectangle())
                }
                .buttonStyle(VdpiPressButtonStyle(haptic: nil))
                .disabled(isReloading)
                .accessibilityLabel(isReloading ? "Reconnecting tunnel" : "Reconnect tunnel")

                Button {
                    dismiss()
                } label: {
                    Image(systemName: "xmark")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(palette.inkPrimary.opacity(0.60))
                        .frame(width: 28, height: 28)
                        .background(
                            Circle()
                                .fill(palette.inkPrimary.opacity(0.08))
                        )
                        .frame(width: 44, height: 44)
                        .contentShape(Rectangle())
                }
                .buttonStyle(VdpiPressButtonStyle(haptic: nil))
                .disabled(isReloading)
                .opacity(isReloading ? 0.35 : 1)
                .accessibilityLabel("Dismiss")
            }
        }
        .padding(.leading, 14)
        .padding(.trailing, 4)
        .padding(.vertical, isCompactHeight ? 2 : 6)
        .frame(minHeight: isCompactHeight ? 48 : 56)
        .frame(maxWidth: 460)
        .vdpiGlass(in: Capsule(), tier: .elevated)
        .dynamicTypeSize(...DynamicTypeSize.xLarge)
        .offset(y: popupDragOffset)
        .accessibilityAction(named: "Dismiss") {
            dismiss()
        }
        .gesture(
            DragGesture(minimumDistance: 6, coordinateSpace: .global)
                .onChanged { value in
                    guard !isReloading else { return }
                    if value.translation.height < 0 {
                        popupDragOffset = value.translation.height
                    } else {
                        popupDragOffset = value.translation.height * 0.25
                    }
                }
                .onEnded { value in
                    guard !isReloading else {
                        popupDragOffset = 0
                        return
                    }
                    let velocityDelta = value.predictedEndTranslation.height - value.translation.height
                    if value.translation.height < -24 || velocityDelta < -48 {
                        dismiss()
                    } else {
                        withAnimation(popupAnimation) {
                            popupDragOffset = 0
                        }
                    }
                }
        )
        .onDisappear {
            popupDragOffset = 0
        }
    }

    private func dismiss() {
        guard !isReloading else { return }
        VdpiHaptics.trigger(.light)
        withAnimation(dismissAnimation) {
            popupDragOffset = 0
            onDismiss()
        }
    }
}

// MARK: - Floating Live Tunnel Accessory Pill

struct LiveTunnelAccessoryPill: View {
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    let phase: TunnelPhase
    let telemetry: TelemetrySnapshot
    let errorMessage: String?
    let isCompactHeight: Bool
    let onTapPill: () -> Void
    let onToggleTunnel: () -> Void

    init(
        phase: TunnelPhase,
        telemetry: TelemetrySnapshot,
        errorMessage: String?,
        isCompactHeight: Bool,
        onTapPill: @escaping () -> Void,
        onToggleTunnel: @escaping () -> Void
    ) {
        self.phase = phase
        self.telemetry = telemetry
        self.errorMessage = errorMessage
        self.isCompactHeight = isCompactHeight
        self.onTapPill = onTapPill
        self.onToggleTunnel = onToggleTunnel
    }

    var body: some View {
        let isStopping = phase == .disconnecting
        let isError = phase == .error
        let pillMinHeight: CGFloat = isCompactHeight ? 44 : 50

        HStack(spacing: 10) {
            Button {
                VdpiHaptics.trigger(.selection)
                onTapPill()
            } label: {
                HStack(spacing: 10) {
                    CalmStatusDot(
                        color: accessoryStatusColor,
                        isBreathing: phase == .connecting,
                        reduceMotion: reduceMotion
                    )

                    VStack(alignment: .leading, spacing: 1) {
                        Text(accessoryTitle)
                            .font(.footnote.weight(.semibold))
                            .foregroundStyle(palette.inkPrimary)
                            .lineLimit(1)

                        Text(accessorySubtitle)
                            .font(.caption)
                            .monospacedDigit()
                            .foregroundStyle(palette.inkSecondary)
                            .contentTransition(.numericText())
                            .lineLimit(1)
                            .truncationMode(.tail)
                    }

                    Spacer(minLength: 4)
                }
                .frame(maxWidth: .infinity, minHeight: pillMinHeight, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("\(accessoryTitle), \(accessorySubtitle). Switch to Tunnel")

            Button {
                onToggleTunnel()
            } label: {
                ZStack {
                    Circle()
                        .fill(palette.inkPrimary.opacity(palette.isDark ? 0.12 : 0.10))
                        .frame(width: isCompactHeight ? 32 : 34, height: isCompactHeight ? 32 : 34)

                    if isStopping {
                        ProgressView()
                            .progressViewStyle(.circular)
                            .controlSize(.mini)
                            .tint(palette.inkPrimary)
                    } else {
                        Image(systemName: isError ? "arrow.clockwise" : "power")
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(palette.inkPrimary)
                    }
                }
                .frame(width: 44, height: 44)
                .contentShape(Circle())
            }
            .buttonStyle(AccessoryStopButtonStyle())
            .disabled(isStopping)
            .accessibilityLabel(isError ? "Reconnect tunnel" : "Disconnect tunnel")
        }
        .padding(.leading, 14)
        .padding(.trailing, 3)
        .frame(minHeight: pillMinHeight)
        .frame(maxWidth: 360)
        .vdpiGlass(in: Capsule(), tier: .elevated, interactive: true)
        .dynamicTypeSize(...DynamicTypeSize.xLarge)
    }

    private var accessoryTitle: String {
        switch phase {
        case .connected: return "Connected"
        case .connecting: return "Connecting..."
        case .disconnecting: return "Disconnecting..."
        case .error: return "Tunnel Error"
        case .disconnected: return "Disconnected"
        }
    }

    private var accessorySubtitle: String {
        switch phase {
        case .connected:
            let uptime = VdpiFormatters.formatUptime(telemetry.uptimeSecs)
            let rx = VdpiFormatters.formatBytes(telemetry.bytesRx)
            return "\(uptime) · ↓ \(rx)"
        case .connecting:
            return "Starting TLS desync & DoH..."
        case .disconnecting:
            return "Closing tunnel interface..."
        case .error:
            return errorMessage ?? "Tap to inspect"
        case .disconnected:
            return "Standby"
        }
    }

    private var accessoryStatusColor: Color {
        switch phase {
        case .connected: return palette.signal
        case .connecting, .disconnecting: return palette.warning
        case .error: return palette.danger
        case .disconnected: return palette.inkMuted
        }
    }
}

struct AccessoryStopButtonStyle: ButtonStyle {
    init() {}

    func makeBody(configuration: Configuration) -> some View {
        StopPressBody(configuration: configuration)
    }

    private struct StopPressBody: View {
        @Environment(\.accessibilityReduceMotion) private var reduceMotion
        let configuration: Configuration

        var body: some View {
            configuration.label
                .scaleEffect(configuration.isPressed && !reduceMotion ? 0.92 : 1.0)
                .opacity(configuration.isPressed ? 0.84 : 1.0)
                .animation(reduceMotion ? nil : VdpiMotion.press, value: configuration.isPressed)
        }
    }
}

// MARK: - Floating Liquid Glass Capsule Tab Bar

struct FloatingGlassTabBar: View {
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorSchemeContrast) private var colorSchemeContrast
    @Environment(\.layoutDirection) private var layoutDirection

    @Binding var selectedTab: VdpiTab
    let phase: TunnelPhase
    let pendingReconnect: Bool
    let isCompactHeight: Bool

    @State private var tabBarWidth: CGFloat = 248
    @State private var isDraggingTabBar: Bool = false
    @Namespace private var tabBarNamespace

    init(
        selectedTab: Binding<VdpiTab>,
        phase: TunnelPhase,
        pendingReconnect: Bool,
        isCompactHeight: Bool
    ) {
        self._selectedTab = selectedTab
        self.phase = phase
        self.pendingReconnect = pendingReconnect
        self.isCompactHeight = isCompactHeight
    }

    private var tabLensAnimation: Animation {
        reduceMotion ? .easeInOut(duration: 0.15) : .spring(response: 0.34, dampingFraction: 0.80)
    }

    var body: some View {
        let tabs = VdpiTab.allCases

        HStack(spacing: 0) {
            ForEach(tabs) { tab in
                let isSelected = (selectedTab == tab)
                Button {
                    selectTab(tab)
                } label: {
                    tabSlotContent(for: tab, isSelected: isSelected)
                        .foregroundStyle(isSelected ? palette.accent : palette.inkPrimary.opacity(0.62))
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .background {
                            if isSelected {
                                tabBarLens
                                    .scaleEffect(
                                        x: (!reduceMotion && isDraggingTabBar) ? 1.07 : 1.0,
                                        y: (!reduceMotion && isDraggingTabBar) ? 1.05 : 1.0
                                    )
                                    .animation(
                                        reduceMotion ? nil : .spring(response: 0.28, dampingFraction: 0.72),
                                        value: isDraggingTabBar
                                    )
                                    .matchedGeometryEffect(id: "vdpi.tab.lens", in: tabBarNamespace)
                            }
                        }
                        .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(tabAccessibilityLabel(for: tab))
                .accessibilityAddTraits(isSelected ? .isSelected : [])
            }
        }
        .padding(isCompactHeight ? 3.5 : 4)
        .frame(maxWidth: isCompactHeight ? 280 : 264)
        .frame(height: isCompactHeight ? 48 : 62)
        .vdpiGlass(in: Capsule(), tier: .elevated)
        .overlay(
            Capsule()
                .strokeBorder(
                    LinearGradient(
                        colors: palette.isDark
                            ? [Color.white.opacity(0.36), Color.white.opacity(0.08), Color.white.opacity(0.16)]
                            : [Color.white.opacity(0.95), Color.white.opacity(0.45), Color.white.opacity(0.65)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    lineWidth: colorSchemeContrast == .increased ? 1.0 : 0.75
                )
                .allowsHitTesting(false)
        )
        .shadow(
            color: Color.black.opacity(palette.isDark ? 0.24 : 0.10),
            radius: 18,
            x: 0,
            y: 8
        )
        .background(
            GeometryReader { proxy in
                Color.clear
                    .onAppear {
                        tabBarWidth = max(proxy.size.width, 1)
                    }
                    .vdpiOnChange(of: proxy.size.width) { width in
                        tabBarWidth = max(width, 1)
                    }
            }
        )
        .simultaneousGesture(
            DragGesture(minimumDistance: 14, coordinateSpace: .local)
                .onChanged { value in
                    guard !tabs.isEmpty else { return }
                    guard abs(value.translation.width) > abs(value.translation.height) else { return }
                    if !isDraggingTabBar { isDraggingTabBar = true }
                    let segmentWidth = tabBarWidth / CGFloat(tabs.count)
                    let rawIdx = min(max(Int(value.location.x / max(segmentWidth, 1)), 0), tabs.count - 1)
                    let targetIndex = layoutDirection == .rightToLeft ? (tabs.count - 1 - rawIdx) : rawIdx
                    selectTab(tabs[targetIndex])
                }
                .onEnded { _ in
                    isDraggingTabBar = false
                }
        )
    }

    @ViewBuilder
    private func tabSlotContent(for tab: VdpiTab, isSelected: Bool) -> some View {
        if isCompactHeight {
            HStack(spacing: 6) {
                Image(systemName: tab.systemImage(selected: isSelected))
                    .font(.system(size: 16, weight: .semibold))
                    .overlay(alignment: .topTrailing) {
                        if tab == .tunnel, let dotColor = tunnelTabStatusDotColor {
                            Circle()
                                .fill(dotColor)
                                .frame(width: 6, height: 6)
                                .offset(x: 3, y: -2)
                                .accessibilityHidden(true)
                        }
                    }

                Text(tab.title)
                    .font(.caption.weight(isSelected ? .semibold : .medium))
                    .dynamicTypeSize(...DynamicTypeSize.large)
                    .lineLimit(1)
            }
        } else {
            VStack(spacing: 3) {
                Image(systemName: tab.systemImage(selected: isSelected))
                    .font(.system(size: 20, weight: isSelected ? .semibold : .medium))
                    .overlay(alignment: .topTrailing) {
                        if tab == .tunnel, let dotColor = tunnelTabStatusDotColor {
                            Circle()
                                .fill(dotColor)
                                .frame(width: 6, height: 6)
                                .offset(x: 5, y: -2)
                                .accessibilityHidden(true)
                        }
                    }

                Text(tab.title)
                    .font(.caption2.weight(isSelected ? .semibold : .medium))
                    .dynamicTypeSize(...DynamicTypeSize.large)
                    .lineLimit(1)
            }
        }
    }

    private var tabBarLens: some View {
        let rimGradient = LinearGradient(
            colors: colorSchemeContrast == .increased
                ? [palette.borderStrong, palette.borderStrong]
                : (palette.isDark
                    ? [Color.white.opacity(0.38), Color.white.opacity(0.06), Color.white.opacity(0.14)]
                    : [Color.white, Color.white.opacity(0.65), Color.black.opacity(0.06)]),
            startPoint: .top,
            endPoint: .bottom
        )
        let rimWidth: CGFloat = colorSchemeContrast == .increased ? 1.0 : 0.67

        return Capsule()
            .fill(
                reduceTransparency
                    ? AnyShapeStyle(palette.surface)
                    : AnyShapeStyle(
                        LinearGradient(
                            colors: palette.isDark
                                ? [Color.white.opacity(0.16), Color.white.opacity(0.07)]
                                : [Color.white.opacity(0.94), Color.white.opacity(0.80)],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )
            )
            .overlay(
                Capsule()
                    .strokeBorder(rimGradient, lineWidth: rimWidth)
                    .allowsHitTesting(false)
            )
            .shadow(
                color: palette.isDark ? .clear : Color.black.opacity(0.08),
                radius: palette.isDark ? 0 : 6,
                x: 0,
                y: palette.isDark ? 0 : 2
            )
    }

    private func selectTab(_ tab: VdpiTab) {
        guard selectedTab != tab else { return }
        VdpiHaptics.trigger(.selection)
        withAnimation(tabLensAnimation) {
            selectedTab = tab
        }
    }

    private var tunnelTabStatusDotColor: Color? {
        switch phase {
        case .connected:
            return pendingReconnect ? palette.warning : palette.signal
        case .connecting:
            return palette.warning
        case .error:
            return palette.danger
        case .disconnected, .disconnecting:
            return nil
        }
    }

    private func tabAccessibilityLabel(for tab: VdpiTab) -> String {
        guard tab == .tunnel else { return tab.title }
        switch phase {
        case .connected:
            return pendingReconnect ? "Tunnel, connected, settings pending" : "Tunnel, connected"
        case .connecting:
            return "Tunnel, connecting"
        case .error:
            return "Tunnel, error"
        case .disconnected, .disconnecting:
            return tab.title
        }
    }
}

// MARK: - Subtle Floating Toast Banner

struct VdpiToastPill: View {
    @Environment(\.vdpiPalette) private var palette

    let message: String
    let isCompactHeight: Bool

    init(message: String, isCompactHeight: Bool) {
        self.message = message
        self.isCompactHeight = isCompactHeight
    }

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(palette.accent)
                .frame(width: 6, height: 6)
                .accessibilityHidden(true)

            Text(message)
                .font(.footnote.weight(.medium))
                .foregroundStyle(palette.inkPrimary)
                .multilineTextAlignment(.center)
                .lineLimit(2)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, isCompactHeight ? 8 : 10)
        .vdpiGlass(in: Capsule(), tier: .elevated)
        .dynamicTypeSize(...DynamicTypeSize.accessibility2)
        .padding(.horizontal, 12)
    }
}

// MARK: - HUD Supporting Containers & Micro-Views

struct VdpiGlassGroupContainer<Content: View>: View {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    let spacing: CGFloat
    @ViewBuilder let content: () -> Content

    init(
        spacing: CGFloat,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.spacing = spacing
        self.content = content
    }

    var body: some View {
        #if compiler(>=6.2) && os(iOS)
        if #available(iOS 26.0, *), !reduceTransparency {
            GlassEffectContainer(spacing: spacing) {
                VStack(spacing: spacing) {
                    content()
                }
            }
        } else {
            VStack(spacing: spacing) {
                content()
            }
        }
        #else
        VStack(spacing: spacing) {
            content()
        }
        #endif
    }
}

private struct CalmStatusDot: View {
    let color: Color
    let isBreathing: Bool
    let reduceMotion: Bool

    @State private var isDimmed = false

    init(color: Color, isBreathing: Bool, reduceMotion: Bool) {
        self.color = color
        self.isBreathing = isBreathing
        self.reduceMotion = reduceMotion
    }

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: 8, height: 8)
            .opacity(isBreathing && !reduceMotion && isDimmed ? 0.45 : 1.0)
            .onAppear {
                syncBreathing()
            }
            .vdpiOnChange(of: isBreathing) { _ in
                syncBreathing()
            }
            .vdpiOnChange(of: reduceMotion) { _ in
                syncBreathing()
            }
            .accessibilityHidden(true)
    }

    private func syncBreathing() {
        guard isBreathing && !reduceMotion else {
            withAnimation(.easeOut(duration: 0.15)) {
                isDimmed = false
            }
            return
        }
        isDimmed = false
        withAnimation(.easeInOut(duration: 1.2).repeatForever(autoreverses: true)) {
            isDimmed = true
        }
    }
}
