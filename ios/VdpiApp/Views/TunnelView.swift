import SwiftUI

struct TunnelView: View {
    var topInset: CGFloat = 0
    var bottomInset: CGFloat = 104
    var showInlineReconnect: Bool = true

    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.verticalSizeClass) private var verticalSizeClass
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass

    @State private var showDiagnosticsSheet = false
    @State private var showLogsSheet = false
    @State private var cacheCleared = false
    @State private var cacheFeedbackTask: Task<Void, Never>?

    // MARK: - Derived State

    private var useTwoPaneLayout: Bool {
        verticalSizeClass == .compact || horizontalSizeClass == .regular
    }

    private var isCompactHeight: Bool {
        verticalSizeClass == .compact
    }

    private var isConnected: Bool { manager.phase == .connected }
    private var isConnecting: Bool { manager.phase == .connecting }
    private var isDisconnecting: Bool { manager.phase == .disconnecting }
    private var isBusy: Bool { isConnecting || isDisconnecting }

    private var heroTitle: String {
        switch manager.phase {
        case .connected: return "Connected"
        case .connecting: return "Connecting"
        case .disconnecting: return "Disconnecting"
        case .disconnected: return "Not Connected"
        case .error: return "Connection Error"
        }
    }

    private var primaryButtonTitle: String {
        switch manager.phase {
        case .disconnected, .error: return "Connect"
        case .connecting: return "Cancel"
        case .connected: return "Disconnect"
        case .disconnecting: return "Disconnecting..."
        }
    }

    private var diagnosticsBadgeColor: Color? {
        if manager.doctorState.running {
            return palette.warning
        }
        if manager.doctorState.error != nil {
            return palette.danger
        }
        if let report = manager.doctorState.report {
            return report.ok ? nil : palette.danger
        }
        return nil
    }

    private var logsBadgeColor: Color? {
        if manager.telemetry.events.contains(where: {
            let level = $0.level.lowercased()
            return level == "error" || level == "err"
        }) {
            return palette.danger
        }
        return nil
    }

    // MARK: - Body

    var body: some View {
        ScrollView {
            Group {
                if useTwoPaneLayout {
                    twoPaneContent
                } else {
                    portraitContent
                }
            }
            .animation(reduceMotion ? nil : VdpiMotion.cardShift, value: manager.phase)
            .animation(reduceMotion ? nil : VdpiMotion.cardShift, value: manager.pendingReconnect)
            .animation(reduceMotion ? nil : VdpiMotion.cardShift, value: showInlineReconnect)
            .animation(reduceMotion ? nil : VdpiMotion.floatingHud, value: topInset)
            .animation(reduceMotion ? nil : VdpiMotion.cardShift, value: useTwoPaneLayout)
            .padding(.horizontal, useTwoPaneLayout ? (isCompactHeight ? 16 : 24) : 16)
            .padding(.top, (isCompactHeight ? 6 : 12) + topInset)
            .padding(.bottom, bottomInset)
        }
        .scrollIndicators(.hidden)
        .onDisappear {
            cacheFeedbackTask?.cancel()
        }
        .sheet(isPresented: $showDiagnosticsSheet) {
            DiagnosticsSheet()
                .environmentObject(manager)
                .environment(\.vdpiPalette, palette)
                .preferredColorScheme(palette.isDark ? .dark : .light)
                .presentationDetents([.medium, .large])
                .presentationDragIndicator(.visible)
        }
        .sheet(isPresented: $showLogsSheet) {
            EngineLogsSheet()
                .environmentObject(manager)
                .environment(\.vdpiPalette, palette)
                .preferredColorScheme(palette.isDark ? .dark : .light)
                .presentationDetents([.medium, .large])
                .presentationDragIndicator(.visible)
        }
    }

    // MARK: - Adaptive Layouts

    private var portraitContent: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerBar

            heroCard
                .padding(.top, 16)

            if manager.pendingReconnect && manager.phase == .connected && showInlineReconnect {
                inlineReconnectCard
                    .padding(.top, 12)
                    .transition(.opacity.combined(with: .scale(scale: 0.98, anchor: .top)))
            }

            if isConnected {
                connectionSection
                    .padding(.top, 24)
            } else {
                profileSection
                    .padding(.top, 24)
            }

            actionsSection
                .padding(.top, 24)
        }
    }

    private var twoPaneContent: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerBar

            HStack(alignment: .top, spacing: 18) {
                leftDashboardColumn
                    .frame(maxWidth: .infinity, alignment: .topLeading)

                rightDashboardColumn
                    .frame(maxWidth: .infinity, alignment: .topLeading)
            }
            .padding(.top, isCompactHeight ? 10 : 18)
        }
        .frame(maxWidth: 880, alignment: .leading)
        .frame(maxWidth: .infinity, alignment: .center)
    }

    private var leftDashboardColumn: some View {
        VStack(alignment: .leading, spacing: isCompactHeight ? 10 : 16) {
            heroCard

            if manager.pendingReconnect && manager.phase == .connected && showInlineReconnect {
                inlineReconnectCard
                    .transition(.opacity.combined(with: .scale(scale: 0.98, anchor: .top)))
            }

            if isCompactHeight {
                clearCacheCard
            } else {
                actionsSection
            }
        }
    }

    private var rightDashboardColumn: some View {
        VStack(alignment: .leading, spacing: isCompactHeight ? 10 : 16) {
            if isConnected {
                connectionSection
            } else {
                profileSection
            }
        }
    }

    // MARK: - Header

    private var headerBar: some View {
        HStack(alignment: .center, spacing: 12) {
            Text("vdpi")
                .font(isCompactHeight ? .title.bold() : .largeTitle.bold())
                .tracking(isCompactHeight ? -0.4 : -0.6)
                .foregroundStyle(palette.inkPrimary)
                .accessibilityAddTraits(.isHeader)

            Spacer(minLength: 8)

            HStack(spacing: 8) {
                GlassCircleButton(
                    systemImage: "stethoscope",
                    accessibilityLabel: "Diagnostics",
                    badgeColor: diagnosticsBadgeColor
                ) {
                    showDiagnosticsSheet = true
                    if manager.doctorState.report == nil && !manager.doctorState.running {
                        manager.runDiagnostics()
                    }
                }

                GlassCircleButton(
                    systemImage: "terminal",
                    accessibilityLabel: "Engine Logs",
                    badgeColor: logsBadgeColor
                ) {
                    showLogsSheet = true
                }
            }
        }
    }

    // MARK: - Hero Card

    private var heroCard: some View {
        InsetGroupedCard(cornerRadius: 16) {
            if isCompactHeight {
                VStack(alignment: .leading, spacing: 14) {
                    HStack(alignment: .center, spacing: 14) {
                        StatusDisc(phase: manager.phase, compact: true)

                        VStack(alignment: .leading, spacing: 3) {
                            Text(heroTitle)
                                .font(.title3.bold())
                                .foregroundStyle(palette.inkPrimary)
                                .lineLimit(1)
                                .minimumScaleFactor(0.85)

                            heroSubtitle(alignment: .leading)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }

                    PrimaryActionButton(
                        title: primaryButtonTitle,
                        isLoading: isDisconnecting,
                        isDestructiveOutline: isConnected || isBusy
                    ) {
                        manager.toggleTunnel()
                    }
                    .accessibilityHint(isConnecting ? "Double tap to cancel connection" : "")
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(16)
            } else {
                VStack(spacing: 0) {
                    StatusDisc(phase: manager.phase)

                    Text(heroTitle)
                        .font(.title2.bold())
                        .foregroundStyle(palette.inkPrimary)
                        .multilineTextAlignment(.center)
                        .padding(.top, 14)

                    heroSubtitle(alignment: .center)
                        .padding(.top, 4)

                    PrimaryActionButton(
                        title: primaryButtonTitle,
                        isLoading: isDisconnecting,
                        isDestructiveOutline: isConnected || isBusy
                    ) {
                        manager.toggleTunnel()
                    }
                    .accessibilityHint(isConnecting ? "Double tap to cancel connection" : "")
                    .padding(.top, 20)
                }
                .frame(maxWidth: .infinity)
                .padding(20)
            }
        }
    }

    @ViewBuilder
    private func heroSubtitle(alignment: TextAlignment = .center) -> some View {
        if let err = manager.errorMessage, manager.phase == .error {
            Text(err)
                .font(.subheadline)
                .foregroundStyle(palette.danger)
                .multilineTextAlignment(alignment)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
        } else if isConnected {
            let t = manager.telemetry
            let resolver = t.dohEnabled ? "\(t.dnsAddr) DoH" : t.dnsAddr
            Text("\(resolver) · \(VdpiFormatters.formatUptime(t.uptimeSecs))")
                .font(.subheadline)
                .monospacedDigit()
                .foregroundStyle(palette.inkSecondary)
                .contentTransition(.numericText())
                .multilineTextAlignment(alignment)
                .lineLimit(1)
                .minimumScaleFactor(0.85)
        } else if manager.phase == .connecting {
            Text("Establishing local tunnel...")
                .font(.subheadline)
                .foregroundStyle(palette.inkSecondary)
                .multilineTextAlignment(alignment)
                .lineLimit(1)
                .minimumScaleFactor(0.85)
        } else if manager.phase == .disconnecting {
            Text("Closing local tunnel...")
                .font(.subheadline)
                .foregroundStyle(palette.inkSecondary)
                .multilineTextAlignment(alignment)
                .lineLimit(1)
                .minimumScaleFactor(0.85)
        } else {
            Text("Local anti-DPI tunnel ready")
                .font(.subheadline)
                .foregroundStyle(palette.inkSecondary)
                .multilineTextAlignment(alignment)
                .lineLimit(1)
                .minimumScaleFactor(0.85)
        }
    }

    // MARK: - Inline Reconnect

    private var inlineReconnectCard: some View {
        let detail = manager.pendingChangeSummary.isEmpty
            ? "Reconnect to apply"
            : manager.pendingChangeSummary

        return InsetGroupedCard(cornerRadius: 16) {
            HStack(spacing: 12) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(palette.warning)
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 2) {
                    Text("Settings Changed")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(palette.inkPrimary)

                    Text(detail)
                        .font(.footnote)
                        .foregroundStyle(palette.inkSecondary)
                        .lineLimit(2)
                }

                Spacer(minLength: 8)

                Button {
                    VdpiHaptics.trigger(.medium)
                    manager.applyChangesLive()
                } label: {
                    ZStack {
                        Text("Reconnect")
                            .font(.subheadline.weight(.semibold))
                            .lineLimit(1)
                            .opacity(manager.isReloading ? 0 : 1)

                        if manager.isReloading {
                            ProgressView()
                                .progressViewStyle(.circular)
                                .controlSize(.mini)
                                .tint(palette.primaryButtonInk)
                                .accessibilityLabel("Reconnecting tunnel")
                        }
                    }
                    .foregroundStyle(palette.primaryButtonInk)
                    .padding(.horizontal, 14)
                    .frame(minHeight: 34)
                    .background(Capsule().fill(palette.primaryButtonBg))
                    .frame(minHeight: 44)
                    .contentShape(Rectangle())
                }
                .buttonStyle(VdpiPressButtonStyle(haptic: nil))
                .disabled(manager.isReloading)
                .accessibilityLabel(manager.isReloading ? "Reconnecting tunnel" : "Reconnect tunnel")
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
        }
    }

    // MARK: - Connection Telemetry

    private var connectionSection: some View {
        let t = manager.telemetry
        let dnsValue = t.dohEnabled ? "\(t.dnsAddr) (DoH)" : t.dnsAddr
        let quicValue = manager.settings.blockQuic ? "\(t.quicBlocked)" : "Allowed"

        return VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "Connection")

            InsetGroupedCard(cornerRadius: 16) {
                VStack(spacing: 0) {
                    keyValueRow("Download", value: VdpiFormatters.formatBytes(t.bytesRx))
                    InsetDivider(leadingInset: 16)
                    keyValueRow("Upload", value: VdpiFormatters.formatBytes(t.bytesTx))
                    InsetDivider(leadingInset: 16)
                    keyValueRow("Strategy", value: VdpiFormatters.formatStageLabel(t.stageLabel))
                    InsetDivider(leadingInset: 16)
                    keyValueRow("DNS", value: dnsValue)
                    InsetDivider(leadingInset: 16)
                    keyValueRow("QUIC Blocked", value: quicValue)
                }
            }
        }
        .transition(.opacity)
    }

    // MARK: - Standby Profile

    private var profileSection: some View {
        let s = manager.settings
        let dnsValue = s.enableDoh ? "\(s.dnsAddr) (DoH)" : s.dnsAddr

        return VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "Profile")

            InsetGroupedCard(cornerRadius: 16) {
                VStack(spacing: 0) {
                    keyValueRow("Mode", value: "\(s.desyncMode.label) (\(s.chunkSize) B)")
                    InsetDivider(leadingInset: 16)
                    keyValueRow("DNS", value: dnsValue)
                    InsetDivider(leadingInset: 16)
                    keyValueRow("QUIC Blocking", value: s.blockQuic ? "On" : "Off")
                    InsetDivider(leadingInset: 16)
                    keyValueRow("On-Demand", value: s.onDemandEnabled ? "On" : "Off")
                }
            }
        }
        .transition(.opacity)
    }

    // MARK: - Actions

    private var actionsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "Actions")

            clearCacheCard
        }
    }

    private var clearCacheCard: some View {
        InsetGroupedCard(cornerRadius: 16) {
            Button {
                triggerClearCache()
            } label: {
                HStack(spacing: 12) {
                    Image(systemName: "arrow.counterclockwise")
                        .font(.body)
                        .foregroundStyle(palette.accent)
                        .frame(width: 24)
                        .accessibilityHidden(true)

                    Text("Clear Engine Cache")
                        .font(.body)
                        .foregroundStyle(palette.inkPrimary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.85)

                    Spacer(minLength: 8)

                    if cacheCleared {
                        HStack(spacing: 4) {
                            Image(systemName: "checkmark")
                                .font(.footnote.weight(.semibold))
                            Text("Cleared")
                                .font(.subheadline)
                        }
                        .foregroundStyle(palette.inkSecondary)
                        .transition(.opacity)
                    }
                }
                .frame(minHeight: 44)
                .padding(.horizontal, 16)
                .padding(.vertical, isCompactHeight ? 4 : 6)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
        }
    }

    // MARK: - Helpers

    private func keyValueRow(_ title: String, value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(title)
                .font(.body)
                .foregroundStyle(palette.inkPrimary)

            Spacer(minLength: 8)

            Text(value)
                .font(.body)
                .monospacedDigit()
                .foregroundStyle(palette.inkSecondary)
                .contentTransition(.numericText())
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .frame(minHeight: isCompactHeight ? 38 : 44)
        .padding(.horizontal, 16)
        .padding(.vertical, isCompactHeight ? 4 : 6)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(value)")
    }

    private func triggerClearCache() {
        VdpiHaptics.trigger(.light)
        let cleared = manager.clearCache()
        cacheFeedbackTask?.cancel()
        guard cleared else {
            withAnimation(reduceMotion ? nil : VdpiMotion.cardShift) {
                cacheCleared = false
            }
            return
        }
        withAnimation(reduceMotion ? nil : VdpiMotion.cardShift) {
            cacheCleared = true
        }
        cacheFeedbackTask = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 1_600_000_000)
            guard !Task.isCancelled else { return }
            withAnimation(reduceMotion ? nil : VdpiMotion.cardShift) {
                cacheCleared = false
            }
        }
    }
}

// MARK: - Quiet Tonal Status Disc

private struct StatusDisc: View {
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.scenePhase) private var scenePhase

    let phase: TunnelPhase
    var compact: Bool = false

    @State private var pulseDimmed = false

    private var isTransitioning: Bool {
        phase == .connecting || phase == .disconnecting
    }

    private var shouldPulse: Bool {
        isTransitioning && !reduceMotion && scenePhase == .active
    }

    private var discFill: Color {
        switch phase {
        case .connected: return palette.signalTint
        case .disconnected: return palette.surfaceRaised
        case .connecting, .disconnecting: return palette.warningTint
        case .error: return palette.dangerTint
        }
    }

    private var symbolName: String {
        switch phase {
        case .connected: return "shield.fill"
        case .disconnected: return "shield"
        case .connecting, .disconnecting: return "shield.lefthalf.filled"
        case .error: return "exclamationmark.shield.fill"
        }
    }

    private var symbolColor: Color {
        switch phase {
        case .connected: return palette.signal
        case .disconnected: return palette.inkSecondary
        case .connecting, .disconnecting: return palette.warning
        case .error: return palette.danger
        }
    }

    var body: some View {
        let discSize: CGFloat = compact ? 52 : 68
        let symbolSize: CGFloat = compact ? 22 : 28

        ZStack {
            Circle()
                .fill(discFill)
                .frame(width: discSize, height: discSize)

            Image(systemName: symbolName)
                .font(.system(size: symbolSize, weight: .semibold))
                .foregroundStyle(symbolColor)
        }
        .opacity(pulseDimmed ? 0.48 : 1.0)
        .accessibilityHidden(true)
        .onAppear {
            syncPulse()
        }
        .vdpiOnChange(of: shouldPulse) { _ in
            syncPulse()
        }
    }

    private func syncPulse() {
        if shouldPulse {
            pulseDimmed = false
            withAnimation(.easeInOut(duration: 1.0).repeatForever(autoreverses: true)) {
                pulseDimmed = true
            }
        } else {
            withAnimation(.easeOut(duration: 0.2)) {
                pulseDimmed = false
            }
        }
    }
}

