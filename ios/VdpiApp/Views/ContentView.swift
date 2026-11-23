import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

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

struct ContentView: View {
    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorSchemeContrast) private var colorSchemeContrast
    @Environment(\.layoutDirection) private var layoutDirection
    @Environment(\.verticalSizeClass) private var verticalSizeClass
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass

    @State private var selectedTab: VdpiTab = .tunnel
    @State private var popupDragOffset: CGFloat = 0
    @State private var bottomSafeInset: CGFloat = 0
    @State private var isKeyboardVisible: Bool = false
    @State private var tabBarWidth: CGFloat = 248
    @State private var isDraggingTabBar: Bool = false
    @Namespace private var tabBarNamespace

    private var isCompactHeight: Bool {
        verticalSizeClass == .compact
    }

    private var contentMaxWidth: CGFloat {
        (isCompactHeight || horizontalSizeClass == .regular) ? 980 : 680
    }

    private var showReconnectPopup: Bool {
        (manager.phase == .connected || manager.phase == .connecting)
            && manager.reconnectPopupVisible
    }

    private var showAccessoryPill: Bool {
        selectedTab == .settings && manager.phase != .disconnected
    }

    private var tabBarBottomOffset: CGFloat {
        if isCompactHeight {
            return max(bottomSafeInset - 6, 8)
        }
        return bottomSafeInset > 0 ? max(bottomSafeInset - 12, 12) : 12
    }

    private var bottomScrimHeight: CGFloat {
        if isCompactHeight {
            return showAccessoryPill
                ? tabBarBottomOffset + 120
                : max(72, tabBarBottomOffset + 72)
        }
        return showAccessoryPill
            ? tabBarBottomOffset + 148
            : max(96, tabBarBottomOffset + 90)
    }

    private var topContentInset: CGFloat {
        guard showReconnectPopup else { return 0 }
        return isCompactHeight ? 62 : 76
    }

    private var bottomContentInset: CGFloat {
        if isCompactHeight {
            return showAccessoryPill
                ? tabBarBottomOffset + 108
                : tabBarBottomOffset + 60
        }
        return showAccessoryPill
            ? tabBarBottomOffset + 136
            : tabBarBottomOffset + 78
    }

    private var popupAnimation: Animation {
        reduceMotion ? .easeInOut(duration: 0.15) : .spring(response: 0.36, dampingFraction: 0.82)
    }

    private var tabLensAnimation: Animation {
        reduceMotion ? .easeInOut(duration: 0.15) : .spring(response: 0.34, dampingFraction: 0.80)
    }

    private var pillAnimation: Animation {
        reduceMotion ? .easeInOut(duration: 0.15) : .easeOut(duration: 0.22)
    }

    private var dismissAnimation: Animation {
        reduceMotion ? .easeInOut(duration: 0.15) : VdpiMotion.dismiss
    }

    private var popupTransition: AnyTransition {
        reduceMotion
            ? .opacity
            : .offset(y: -24).combined(with: .opacity)
    }

    private var bottomItemTransition: AnyTransition {
        reduceMotion
            ? .opacity
            : .offset(y: 12).combined(with: .opacity)
    }

    var body: some View {
        ZStack {
            // Z0: Clean solid Apple canvas background (no ambient orbs or blur)
            palette.canvas
                .ignoresSafeArea()

            // Z0: State-preserving ZStack so scroll offsets and unsaved drafts persist across tabs
            ZStack {
                TunnelView(
                    topInset: topContentInset,
                    bottomInset: bottomContentInset,
                    showInlineReconnect: !showReconnectPopup
                )
                    .vdpiSoftBottomScrollEdge()
                    .opacity(selectedTab == .tunnel ? 1 : 0)
                    .allowsHitTesting(selectedTab == .tunnel)
                    .accessibilityHidden(selectedTab != .tunnel)

                SettingsView(topInset: topContentInset, bottomInset: bottomContentInset)
                    .vdpiSoftBottomScrollEdge()
                    .opacity(selectedTab == .settings ? 1 : 0)
                    .allowsHitTesting(selectedTab == .settings)
                    .accessibilityHidden(selectedTab != .settings)
            }
            .frame(maxWidth: contentMaxWidth, maxHeight: .infinity)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(safeAreaReader)
        // Z10 + Z20: Scroll edge dissolution scrim behind floating bottom chrome
        .overlay(alignment: .bottom) {
            ZStack(alignment: .bottom) {
                ScrollEdgeFadeScrim(height: bottomScrimHeight, fromBottom: true)
                    .opacity(isKeyboardVisible ? 0 : 1)

                bottomDockStack
                    .padding(.bottom, tabBarBottomOffset)
                    .opacity(isKeyboardVisible ? 0 : 1)
                    .offset(y: isKeyboardVisible && !reduceMotion ? 24 : 0)
                    .allowsHitTesting(!isKeyboardVisible)
                    .accessibilityHidden(isKeyboardVisible)
            }
            .ignoresSafeArea(.container, edges: .bottom)
            .ignoresSafeArea(.keyboard, edges: .bottom)
        }
        // Z30: Top-floating "Settings Changed" Liquid Glass popup across all tabs
        .overlay(alignment: .top) {
            if showReconnectPopup {
                reconnectPopup
                    .padding(.horizontal, 16)
                    .padding(.top, isCompactHeight ? 4 : 8)
                    .transition(popupTransition)
            }
        }
        .animation(popupAnimation, value: showReconnectPopup)
        .animation(pillAnimation, value: showAccessoryPill)
        .animation(pillAnimation, value: manager.toastMessage)
        .animation(pillAnimation, value: isKeyboardVisible)
        #if canImport(UIKit)
        .onReceive(NotificationCenter.default.publisher(for: UIResponder.keyboardWillShowNotification)) { notification in
            if let frame = notification.userInfo?[UIResponder.keyboardFrameEndUserInfoKey] as? CGRect {
                isKeyboardVisible = frame.height > 0
            } else {
                isKeyboardVisible = true
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: UIResponder.keyboardWillHideNotification)) { _ in
            isKeyboardVisible = false
        }
        #endif
    }

    private var safeAreaReader: some View {
        GeometryReader { proxy in
            Color.clear
                .onAppear {
                    bottomSafeInset = proxy.safeAreaInsets.bottom
                }
                .vdpiOnChange(of: proxy.safeAreaInsets.bottom) { newInset in
                    bottomSafeInset = newInset
                }
        }
        .ignoresSafeArea(.keyboard, edges: .bottom)
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }

    // MARK: - Z30: Top-Floating "Settings Changed" Liquid Glass Popup

    private var reconnectPopup: some View {
        let subtitle: String = manager.pendingChangeSummary.isEmpty
            ? "Reconnect to apply"
            : "Reconnect to apply · \(manager.pendingChangeSummary)"

        return HStack(spacing: 10) {
            Group {
                if manager.isReloading && !reduceMotion {
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
                    manager.applyChangesLive()
                } label: {
                    ZStack {
                        Text("Reconnect")
                            .font(.footnote.weight(.semibold))
                            .lineLimit(1)
                            .opacity(manager.isReloading ? 0 : 1)

                        if manager.isReloading {
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
                .disabled(manager.isReloading)
                .accessibilityLabel(manager.isReloading ? "Reconnecting tunnel" : "Reconnect tunnel")

                Button {
                    dismissReconnectPopup()
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
                .disabled(manager.isReloading)
                .opacity(manager.isReloading ? 0.35 : 1)
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
            dismissReconnectPopup()
        }
        .gesture(
            DragGesture(minimumDistance: 6, coordinateSpace: .global)
                .onChanged { value in
                    guard !manager.isReloading else { return }
                    if value.translation.height < 0 {
                        popupDragOffset = value.translation.height
                    } else {
                        popupDragOffset = value.translation.height * 0.25
                    }
                }
                .onEnded { value in
                    guard !manager.isReloading else {
                        popupDragOffset = 0
                        return
                    }
                    let velocityDelta = value.predictedEndTranslation.height - value.translation.height
                    if value.translation.height < -24 || velocityDelta < -48 {
                        dismissReconnectPopup()
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

    private func dismissReconnectPopup() {
        guard !manager.isReloading else { return }
        VdpiHaptics.trigger(.light)
        withAnimation(dismissAnimation) {
            popupDragOffset = 0
            manager.dismissReconnectPopup()
        }
    }

    // MARK: - Z20: Bottom Floating HUD Stack

    private var bottomDockStack: some View {
        let stackSpacing: CGFloat = isCompactHeight ? 6 : 8

        return VStack(spacing: stackSpacing) {
            if let toast = manager.toastMessage {
                toastPill(toast)
                    .transition(bottomItemTransition)
            }

            VdpiGlassGroupContainer(spacing: stackSpacing) {
                if showAccessoryPill {
                    liveTunnelAccessoryPill
                        .transition(bottomItemTransition)
                }

                floatingTabBar
            }
        }
        .padding(.horizontal, 16)
    }

    private func toastPill(_ message: String) -> some View {
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

    // MARK: - Floating Live Tunnel Accessory Pill

    private var liveTunnelAccessoryPill: some View {
        let isStopping = manager.phase == .disconnecting
        let isError = manager.phase == .error
        let pillMinHeight: CGFloat = isCompactHeight ? 44 : 50

        return HStack(spacing: 10) {
            Button {
                VdpiHaptics.trigger(.selection)
                withAnimation(tabLensAnimation) {
                    selectedTab = .tunnel
                }
            } label: {
                HStack(spacing: 10) {
                    CalmStatusDot(
                        color: accessoryStatusColor,
                        isBreathing: manager.phase == .connecting,
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
                manager.toggleTunnel()
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
        switch manager.phase {
        case .connected: return "Connected"
        case .connecting: return "Connecting..."
        case .disconnecting: return "Disconnecting..."
        case .error: return "Tunnel Error"
        case .disconnected: return "Disconnected"
        }
    }

    private var accessorySubtitle: String {
        switch manager.phase {
        case .connected:
            let uptime = VdpiFormatters.formatUptime(manager.telemetry.uptimeSecs)
            let rx = VdpiFormatters.formatBytes(manager.telemetry.bytesRx)
            return "\(uptime) · ↓ \(rx)"
        case .connecting:
            return "Starting TLS desync & DoH..."
        case .disconnecting:
            return "Closing tunnel interface..."
        case .error:
            return manager.errorMessage ?? "Tap to inspect"
        case .disconnected:
            return "Standby"
        }
    }

    private var accessoryStatusColor: Color {
        switch manager.phase {
        case .connected: return palette.signal
        case .connecting, .disconnecting: return palette.warning
        case .error: return palette.danger
        case .disconnected: return palette.inkMuted
        }
    }

    // MARK: - Floating Liquid Glass Capsule Tab Bar

    private var floatingTabBar: some View {
        let tabs = VdpiTab.allCases

        return HStack(spacing: 0) {
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
        switch manager.phase {
        case .connected:
            return manager.pendingReconnect ? palette.warning : palette.signal
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
        switch manager.phase {
        case .connected:
            return manager.pendingReconnect ? "Tunnel, connected, settings pending" : "Tunnel, connected"
        case .connecting:
            return "Tunnel, connecting"
        case .error:
            return "Tunnel, error"
        case .disconnected, .disconnecting:
            return tab.title
        }
    }
}

// MARK: - HUD Supporting Micro-Views

private struct CalmStatusDot: View {
    let color: Color
    let isBreathing: Bool
    let reduceMotion: Bool

    @State private var isDimmed = false

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

private struct AccessoryStopButtonStyle: ButtonStyle {
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

private struct VdpiGlassGroupContainer<Content: View>: View {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    let spacing: CGFloat
    @ViewBuilder let content: () -> Content

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

private extension View {
    @ViewBuilder
    func vdpiSoftBottomScrollEdge() -> some View {
        #if compiler(>=6.2) && os(iOS)
        if #available(iOS 26.0, *) {
            scrollEdgeEffectStyle(.soft, for: .bottom)
        } else {
            self
        }
        #else
        self
        #endif
    }
}
