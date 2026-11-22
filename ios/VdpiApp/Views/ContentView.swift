import SwiftUI

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
        switch self {
        case .tunnel: return "shield.lefthalf.filled"
        case .settings: return "slider.horizontal.3"
        }
    }
}

struct ContentView: View {
    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    @State private var selectedTab: VdpiTab = .tunnel
    @State private var popupDragOffset: CGFloat = 0
    @Namespace private var tabBarNamespace

    private var showReconnectPopup: Bool {
        (manager.reconnectPopupVisible && (manager.phase == .connected || manager.phase == .connecting))
            || manager.isReloading
    }

    private var showMiniBar: Bool {
        selectedTab == .settings && manager.phase != .disconnected
    }

    private var topContentInset: CGFloat {
        showReconnectPopup ? 84 : 0
    }

    private var bottomContentInset: CGFloat {
        showMiniBar ? 164 : 104
    }

    var body: some View {
        ZStack {
            VdpiAmbientBackdrop(phase: manager.phase)

            // State-preserving ZStack so scroll offsets and unsaved drafts persist across tabs.
            ZStack {
                TunnelView(topInset: topContentInset, bottomInset: bottomContentInset)
                    .opacity(selectedTab == .tunnel ? 1 : 0)
                    .allowsHitTesting(selectedTab == .tunnel)
                    .accessibilityHidden(selectedTab != .tunnel)

                SettingsView(topInset: topContentInset, bottomInset: bottomContentInset)
                    .opacity(selectedTab == .settings ? 1 : 0)
                    .allowsHitTesting(selectedTab == .settings)
                    .accessibilityHidden(selectedTab != .settings)
            }
            .frame(maxWidth: 680, maxHeight: .infinity)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .overlay(alignment: .top) {
            if showReconnectPopup {
                reconnectPopup
                    .padding(.horizontal, 16)
                    .padding(.top, 8)
                    .transition(
                        .move(edge: .top)
                            .combined(with: .opacity)
                            .combined(with: .scale(scale: 0.94, anchor: .top))
                    )
            }
        }
        .overlay(alignment: .bottom) {
            bottomDockStack
                .ignoresSafeArea(.keyboard, edges: .bottom)
        }
        .animation(VdpiMotion.floatingHud, value: showReconnectPopup)
        .animation(VdpiMotion.floatingHud, value: showMiniBar)
        .animation(VdpiMotion.floatingHud, value: manager.toastMessage)
    }

    // MARK: - Top Floating Reconnect Popup

    private var reconnectPopup: some View {
        let subtitle: String = manager.pendingChangeSummary.isEmpty
            ? "Reconnect to apply"
            : "Reconnect · \(manager.pendingChangeSummary)"

        return GlassPanel(
            cornerRadius: 24,
            tier: .elevated,
            tint: palette.warningTint,
            borderAccent: palette.warning
        ) {
            HStack(spacing: 11) {
                RotatingSyncIcon(
                    tint: palette.warning,
                    background: palette.warningTint,
                    isFast: manager.isReloading,
                    reduceMotion: reduceMotion
                )

                VStack(alignment: .leading, spacing: 2) {
                    Text("Settings changed")
                        .font(.system(size: 13.5, weight: .semibold))
                        .foregroundStyle(palette.inkPrimary)
                        .lineLimit(1)

                    Text(subtitle)
                        .font(.system(size: 11.5, weight: .medium, design: .monospaced))
                        .foregroundStyle(palette.inkSecondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                HStack(spacing: 6) {
                    Button {
                        VdpiHaptics.trigger(.medium)
                        manager.applyChangesLive()
                    } label: {
                        Group {
                            if manager.isReloading {
                                ProgressView()
                                    .progressViewStyle(.circular)
                                    .tint(palette.primaryButtonInk)
                                    .scaleEffect(0.76)
                            } else {
                                Text("Reconnect")
                                    .font(.system(size: 12.5, weight: .semibold))
                                    .lineLimit(1)
                            }
                        }
                        .foregroundStyle(palette.primaryButtonInk)
                        .padding(.horizontal, 13)
                        .frame(minWidth: 86, minHeight: 34)
                        .background(palette.primaryButtonBg)
                        .clipShape(Capsule())
                    }
                    .buttonStyle(VdpiPressButtonStyle(haptic: nil))
                    .disabled(manager.isReloading)

                    Button {
                        VdpiHaptics.trigger(.light)
                        withAnimation(VdpiMotion.dismiss) {
                            popupDragOffset = 0
                            manager.dismissReconnectPopup()
                        }
                    } label: {
                        Image(systemName: "xmark")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundStyle(palette.inkSecondary)
                            .frame(width: 28, height: 28)
                            .background(palette.surfaceRaised.opacity(palette.isDark ? 0.65 : 0.72))
                            .clipShape(Circle())
                            .overlay(
                                Circle()
                                    .strokeBorder(palette.border, lineWidth: 0.75)
                            )
                            .contentShape(Circle())
                    }
                    .buttonStyle(VdpiPressButtonStyle(haptic: nil))
                    .disabled(manager.isReloading)
                    .opacity(manager.isReloading ? 0.35 : 1)
                    .accessibilityLabel("Dismiss reconnect banner")
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
        }
        .frame(maxWidth: 440)
        .offset(y: popupDragOffset)
        .gesture(
            DragGesture(minimumDistance: 6)
                .onChanged { value in
                    guard !manager.isReloading else { return }
                    if value.translation.height < 0 {
                        popupDragOffset = value.translation.height
                    } else {
                        popupDragOffset = value.translation.height * 0.14
                    }
                }
                .onEnded { value in
                    guard !manager.isReloading else {
                        popupDragOffset = 0
                        return
                    }
                    if value.translation.height < -24 || value.predictedEndTranslation.height < -48 {
                        VdpiHaptics.trigger(.light)
                        withAnimation(VdpiMotion.dismiss) {
                            popupDragOffset = 0
                            manager.dismissReconnectPopup()
                        }
                    } else {
                        withAnimation(VdpiMotion.floatingHud) {
                            popupDragOffset = 0
                        }
                    }
                }
        )
    }

    // MARK: - Bottom Floating Dock Stack

    private var bottomDockStack: some View {
        VStack(spacing: 10) {
            if let toast = manager.toastMessage {
                toastPill(toast)
                    .transition(
                        .move(edge: .bottom)
                            .combined(with: .opacity)
                            .combined(with: .scale(scale: 0.94, anchor: .bottom))
                    )
            }

            if showMiniBar {
                liveTunnelMiniBar
                    .transition(
                        .move(edge: .bottom)
                            .combined(with: .opacity)
                            .combined(with: .scale(scale: 0.94, anchor: .bottom))
                    )
            }

            floatingTabBar
        }
        .padding(.horizontal, 16)
        .padding(.bottom, 10)
    }

    private func toastPill(_ message: String) -> some View {
        HStack(spacing: 8) {
            Circle()
                .fill(palette.signal)
                .frame(width: 6, height: 6)
            Text(message)
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(palette.inkPrimary)
                .multilineTextAlignment(.center)
                .lineLimit(2)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .vdpiGlass(in: Capsule(), tier: .elevated)
        .padding(.horizontal, 12)
    }

    private var liveTunnelMiniBar: some View {
        let phaseDotColor = miniBarPhaseColor
        let shouldPulse = manager.phase == .connected || manager.phase == .connecting
        let isStopping = manager.phase == .disconnecting

        return HStack(spacing: 10) {
            Button {
                VdpiHaptics.trigger(.selection)
                withAnimation(VdpiMotion.tabLens) {
                    selectedTab = .tunnel
                }
            } label: {
                HStack(spacing: 10) {
                    PulsingStatusDot(
                        color: phaseDotColor,
                        isPulsing: shouldPulse,
                        reduceMotion: reduceMotion
                    )

                    VStack(alignment: .leading, spacing: 1) {
                        Text(miniBarTitle)
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(palette.inkPrimary)
                            .lineLimit(1)

                        Text(miniBarSubtitle)
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                            .monospacedDigit()
                            .foregroundStyle(palette.inkSecondary)
                            .contentTransition(.numericText())
                            .lineLimit(1)
                            .truncationMode(.tail)
                    }

                    Spacer(minLength: 4)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("\(miniBarTitle), \(miniBarSubtitle). Switch to Tunnel")

            Button {
                VdpiHaptics.trigger(.medium)
                manager.toggleTunnel()
            } label: {
                ZStack {
                    if isStopping {
                        ProgressView()
                            .progressViewStyle(.circular)
                            .tint(palette.inkPrimary)
                            .scaleEffect(0.75)
                    } else {
                        Image(systemName: manager.phase == .error ? "arrow.clockwise" : "power")
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(miniBarPowerTint)
                    }
                }
                .frame(width: 36, height: 36)
                .vdpiGlass(
                    in: Circle(),
                    tier: .regular,
                    tint: miniBarPowerBgTint,
                    borderAccent: miniBarPowerBorder,
                    interactive: true
                )
            }
            .buttonStyle(VdpiPressButtonStyle(haptic: nil))
            .disabled(isStopping)
            .accessibilityLabel(
                manager.phase == .connected || manager.phase == .connecting
                    ? "Disconnect tunnel"
                    : "Reconnect tunnel"
            )
        }
        .padding(.leading, 14)
        .padding(.trailing, 8)
        .frame(height: 52)
        .frame(maxWidth: 400)
        .vdpiGlass(
            in: Capsule(),
            tier: .elevated,
            tint: miniBarGlassTint,
            borderAccent: miniBarBorderAccent,
            interactive: true
        )
    }

    private var miniBarTitle: String {
        switch manager.phase {
        case .connected: return "Protected"
        case .connecting: return "Connecting"
        case .disconnecting: return "Stopping"
        case .error: return "Error"
        case .disconnected: return "Standby"
        }
    }

    private var miniBarSubtitle: String {
        switch manager.phase {
        case .connected:
            let uptime = VdpiFormatters.formatUptime(manager.telemetry.uptimeSecs)
            return "Up \(uptime) · S\(manager.telemetry.stageNumber) · \(VdpiFormatters.formatBytes(manager.telemetry.bytesRx))"
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

    private var miniBarPhaseColor: Color {
        switch manager.phase {
        case .connected: return manager.pendingReconnect ? palette.warning : palette.signal
        case .connecting, .disconnecting: return palette.warning
        case .error: return palette.danger
        case .disconnected: return palette.inkMuted
        }
    }

    private var miniBarGlassTint: Color? {
        switch manager.phase {
        case .connected: return manager.pendingReconnect ? palette.warningTint : palette.signalTint
        case .connecting, .disconnecting: return palette.warningTint
        case .error: return palette.dangerTint
        case .disconnected: return nil
        }
    }

    private var miniBarBorderAccent: Color? {
        switch manager.phase {
        case .connected: return manager.pendingReconnect ? palette.warning : palette.signal
        case .connecting, .disconnecting: return palette.warning
        case .error: return palette.danger
        case .disconnected: return nil
        }
    }

    private var miniBarPowerTint: Color {
        switch manager.phase {
        case .connected: return palette.signal
        case .connecting, .disconnecting: return palette.warning
        case .error: return palette.danger
        case .disconnected: return palette.inkPrimary
        }
    }

    private var miniBarPowerBgTint: Color? {
        switch manager.phase {
        case .connected: return palette.signalTint
        case .connecting, .disconnecting: return palette.warningTint
        case .error: return palette.dangerTint
        case .disconnected: return nil
        }
    }

    private var miniBarPowerBorder: Color? {
        switch manager.phase {
        case .connected: return palette.signal
        case .connecting, .disconnecting: return palette.warning
        case .error: return palette.danger
        case .disconnected: return nil
        }
    }

    // MARK: - Floating Liquid Glass Capsule Tab Bar

    private var floatingTabBar: some View {
        HStack(spacing: 4) {
            ForEach(VdpiTab.allCases) { tab in
                let isSelected = (selectedTab == tab)
                Button {
                    guard selectedTab != tab else { return }
                    VdpiHaptics.trigger(.selection)
                    withAnimation(VdpiMotion.tabLens) {
                        selectedTab = tab
                    }
                } label: {
                    HStack(spacing: 7) {
                        Image(systemName: tab.systemImage)
                            .font(.system(size: 14, weight: isSelected ? .semibold : .medium))
                            .overlay(alignment: .topTrailing) {
                                if tab == .tunnel, let dotColor = tunnelTabStatusDotColor {
                                    Circle()
                                        .fill(dotColor)
                                        .frame(width: 6, height: 6)
                                        .overlay(
                                            Circle()
                                                .strokeBorder(
                                                    palette.isDark ? Color.black.opacity(0.75) : Color.white.opacity(0.95),
                                                    lineWidth: 1
                                                )
                                        )
                                        .offset(x: 3.5, y: -2.5)
                                }
                            }

                        Text(tab.title)
                            .font(.system(size: 13, weight: isSelected ? .semibold : .medium))
                            .lineLimit(1)
                    }
                    .foregroundStyle(isSelected ? palette.inkPrimary : palette.inkMuted)
                    .scaleEffect(isSelected ? 1.0 : 0.96)
                    .frame(maxWidth: .infinity)
                    .frame(minHeight: 44)
                    .background {
                        if isSelected {
                            Capsule()
                                .fill(palette.glassLensFill)
                                .overlay(
                                    Capsule()
                                        .strokeBorder(palette.specularRim(), lineWidth: 0.9)
                                )
                                .shadow(
                                    color: palette.shadowColor.opacity(palette.isDark ? 0.45 : 0.65),
                                    radius: 6,
                                    x: 0,
                                    y: 2
                                )
                                .matchedGeometryEffect(id: "vdpi.tab.lens", in: tabBarNamespace)
                        }
                    }
                    .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(isSelected ? .isSelected : [])
            }
        }
        .padding(5)
        .frame(maxWidth: 270)
        .vdpiGlass(in: Capsule(), tier: .elevated)
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
}

// MARK: - HUD Supporting Micro-Views

private struct RotatingSyncIcon: View {
    let tint: Color
    let background: Color
    let isFast: Bool
    let reduceMotion: Bool

    @State private var angle: Double = 0

    var body: some View {
        ZStack {
            Circle()
                .fill(background)
                .overlay(
                    Circle()
                        .strokeBorder(tint.opacity(0.38), lineWidth: 1)
                )
                .frame(width: 34, height: 34)

            Image(systemName: "arrow.triangle.2.circlepath")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(tint)
                .rotationEffect(.degrees(reduceMotion ? 0 : angle))
        }
        .onAppear {
            startSpin(fast: isFast)
        }
        .vdpiOnChange(of: isFast) { fast in
            startSpin(fast: fast)
        }
        .accessibilityHidden(true)
    }

    private func startSpin(fast: Bool) {
        guard !reduceMotion else {
            angle = 0
            return
        }
        angle = 0
        withAnimation(.linear(duration: fast ? 0.9 : 4.2).repeatForever(autoreverses: false)) {
            angle = 360
        }
    }
}

private struct PulsingStatusDot: View {
    let color: Color
    let isPulsing: Bool
    let reduceMotion: Bool

    @State private var pulseExpanded = false

    var body: some View {
        ZStack {
            if isPulsing && !reduceMotion {
                Circle()
                    .fill(color.opacity(pulseExpanded ? 0.0 : 0.42))
                    .frame(width: 18, height: 18)
                    .scaleEffect(pulseExpanded ? 1.35 : 0.55)
            }
            Circle()
                .fill(color)
                .frame(width: 8, height: 8)
                .shadow(color: color.opacity(0.5), radius: 4, x: 0, y: 0)
        }
        .frame(width: 18, height: 18)
        .onAppear {
            updatePulse()
        }
        .vdpiOnChange(of: isPulsing) { _ in
            updatePulse()
        }
        .accessibilityHidden(true)
    }

    private func updatePulse() {
        guard isPulsing && !reduceMotion else {
            pulseExpanded = false
            return
        }
        pulseExpanded = false
        withAnimation(.easeOut(duration: 1.5).repeatForever(autoreverses: false)) {
            pulseExpanded = true
        }
    }
}
