import SwiftUI

struct TunnelView: View {
    var topInset: CGFloat = 0
    var bottomInset: CGFloat = 104
    var showInlineReconnect: Bool = true

    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.appLanguage) private var appLanguage
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.verticalSizeClass) private var verticalSizeClass
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass

    @State private var showDiagnosticsSheet = false
    @State private var showLogsSheet = false
    @State private var cacheCleared = false
    @State private var cacheFeedbackTask: Task<Void, Never>?

    // MARK: - Derived State

    private var l10n: L10n.Catalog {
        L10n.catalog(for: appLanguage)
    }

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
        case .connected: return l10n.heroConnected
        case .connecting: return l10n.heroConnecting
        case .disconnecting: return l10n.heroDisconnecting
        case .disconnected: return l10n.heroNotConnected
        case .error: return l10n.heroConnectionError
        }
    }

    private var primaryButtonTitle: String {
        switch manager.phase {
        case .disconnected, .error: return l10n.buttonConnect
        case .connecting: return l10n.cancel
        case .connected: return l10n.buttonDisconnect
        case .disconnecting: return l10n.buttonDisconnecting
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
            .animation(reduceMotion ? nil : VdpiMotion.cardShift, value: manager.availableUpdate != nil)
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
                .environment(\.appLanguage, appLanguage)
                .environment(\.locale, l10n.locale)
                .preferredColorScheme(palette.isDark ? .dark : .light)
                .presentationDetents([.medium, .large])
                .presentationDragIndicator(.visible)
        }
        .sheet(isPresented: $showLogsSheet) {
            EngineLogsSheet()
                .environmentObject(manager)
                .environment(\.vdpiPalette, palette)
                .environment(\.appLanguage, appLanguage)
                .environment(\.locale, l10n.locale)
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

            if let update = manager.availableUpdate {
                updateAvailableCard(update)
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

            if let update = manager.availableUpdate {
                updateAvailableCard(update)
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
                    accessibilityLabel: l10n.diagnosticsTitle,
                    badgeColor: diagnosticsBadgeColor
                ) {
                    showDiagnosticsSheet = true
                    if manager.doctorState.report == nil && !manager.doctorState.running {
                        manager.runDiagnostics()
                    }
                }

                GlassCircleButton(
                    systemImage: "terminal",
                    accessibilityLabel: l10n.engineLogsTitle,
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
                    .accessibilityHint(isConnecting ? l10n.accessibilityCancelConnectionHint : "")
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
                    .accessibilityHint(isConnecting ? l10n.accessibilityCancelConnectionHint : "")
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
                .lineLimit(4)
                .fixedSize(horizontal: false, vertical: true)
        } else if isConnected {
            let t = manager.telemetry
            let resolver = Self.displayDnsLabel(
                t.dnsAddr,
                dohEnabled: t.dohEnabled,
                parenthesizedDoh: false,
                customDohFallback: l10n.customDoh
            )
            Text("\(resolver) · \(VdpiFormatters.formatUptime(t.uptimeSecs))")
                .font(.subheadline)
                .monospacedDigit()
                .foregroundStyle(palette.inkSecondary)
                .contentTransition(.numericText())
                .animation(reduceMotion ? nil : .easeOut(duration: 0.2), value: t.uptimeSecs)
                .multilineTextAlignment(alignment)
                .lineLimit(1)
                .minimumScaleFactor(0.85)
        } else if manager.phase == .connecting {
            Text(l10n.subtitleEstablishing)
                .font(.subheadline)
                .foregroundStyle(palette.inkSecondary)
                .multilineTextAlignment(alignment)
                .lineLimit(1)
                .minimumScaleFactor(0.85)
        } else if manager.phase == .disconnecting {
            Text(l10n.subtitleClosing)
                .font(.subheadline)
                .foregroundStyle(palette.inkSecondary)
                .multilineTextAlignment(alignment)
                .lineLimit(1)
                .minimumScaleFactor(0.85)
        } else {
            Text(l10n.subtitleReady)
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
            ? l10n.reconnectToApply
            : manager.pendingChangeSummary

        return InsetGroupedCard(cornerRadius: 16) {
            HStack(spacing: 12) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(palette.warning)
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 2) {
                    Text(l10n.settingsChangedTitle)
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
                        Text(l10n.reconnectButton)
                            .font(.subheadline.weight(.semibold))
                            .lineLimit(1)
                            .opacity(manager.isReloading ? 0 : 1)

                        if manager.isReloading {
                            ProgressView()
                                .progressViewStyle(.circular)
                                .controlSize(.mini)
                                .tint(palette.primaryButtonInk)
                                .accessibilityLabel(l10n.accessibilityReconnectingTunnel)
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
                .accessibilityLabel(manager.isReloading ? l10n.accessibilityReconnectingTunnel : l10n.accessibilityReconnectTunnel)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
        }
    }

    // MARK: - Update Banner

    private func updateAvailableCard(_ update: VdpiUpdateInfo) -> some View {
        let versionLabel = update.latestVersion.lowercased().hasPrefix("v")
            ? update.latestVersion
            : "v\(update.latestVersion)"

        return InsetGroupedCard(cornerRadius: 16) {
            HStack(spacing: 10) {
                Circle()
                    .fill(palette.accent)
                    .frame(width: 6, height: 6)
                    .accessibilityHidden(true)

                Text(l10n.updateAvailableBanner(version: versionLabel))
                    .font(.subheadline.weight(.medium))
                    .foregroundStyle(palette.inkPrimary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.85)

                Spacer(minLength: 8)

                if let releaseURL = URL(string: update.releaseURL) {
                    Link(destination: releaseURL) {
                        HStack(spacing: 3) {
                            Text("GitHub")
                                .font(.footnote.weight(.semibold))
                            Image(systemName: "arrow.up.right")
                                .font(.caption2.weight(.semibold))
                        }
                        .foregroundStyle(palette.accent)
                        .frame(minHeight: 44)
                        .padding(.horizontal, 6)
                        .contentShape(Rectangle())
                    }
                    .accessibilityLabel(l10n.accessibilityOpenRelease(version: versionLabel))
                }

                Button {
                    VdpiHaptics.trigger(.light)
                    withAnimation(reduceMotion ? nil : VdpiMotion.cardShift) {
                        manager.dismissAvailableUpdate()
                    }
                } label: {
                    Image(systemName: "xmark")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(palette.inkMuted)
                        .frame(width: 28, height: 28)
                        .background(
                            Circle()
                                .fill(palette.surfaceRaised)
                        )
                        .frame(width: 44, height: 44)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(l10n.accessibilityDismissUpdate)
            }
            .padding(.leading, 16)
            .padding(.trailing, 4)
            .padding(.vertical, 4)
        }
    }

    // MARK: - Connection Telemetry

    private var connectionSection: some View {
        let t = manager.telemetry
        let dnsValue = Self.displayDnsLabel(
            t.dnsAddr,
            dohEnabled: t.dohEnabled,
            parenthesizedDoh: true,
            customDohFallback: l10n.customDoh
        )
        let effectiveBlockQuic = manager.appliedConfig?.blockQuic ?? manager.settings.blockQuic
        let quicValue = effectiveBlockQuic ? "\(t.quicBlocked)" : l10n.quicAllowed

        return VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: l10n.sectionConnection)

            InsetGroupedCard(cornerRadius: 16) {
                VStack(spacing: 0) {
                    numericMetricRow(l10n.metricDownload, value: VdpiFormatters.formatBytes(t.bytesRx), trigger: t.bytesRx)
                    InsetDivider(leadingInset: 16)
                    numericMetricRow(l10n.metricUpload, value: VdpiFormatters.formatBytes(t.bytesTx), trigger: t.bytesTx)
                    InsetDivider(leadingInset: 16)
                    numericMetricRow(l10n.metricUptime, value: VdpiFormatters.formatUptime(t.uptimeSecs), trigger: t.uptimeSecs)
                    InsetDivider(leadingInset: 16)
                    ThroughputSparkline(
                        samples: manager.throughputSamples,
                        currentRateBytesPerSec: manager.currentRateBytesPerSec
                    )
                    InsetDivider(leadingInset: 16)
                    keyValueRow(l10n.metricStrategy, value: VdpiFormatters.formatStageLabel(t.stageLabel, language: appLanguage))
                    InsetDivider(leadingInset: 16)
                    keyValueRow(l10n.metricDns, value: dnsValue)
                    InsetDivider(leadingInset: 16)
                    keyValueRow(l10n.metricQuicBlocked, value: quicValue)
                }
            }
        }
        .transition(.opacity)
    }

    // MARK: - Standby Profile

    private var profileSection: some View {
        let s = manager.settings
        let dnsValue = Self.displayDnsLabel(
            s.dnsAddr,
            dohEnabled: s.enableDoh,
            parenthesizedDoh: true,
            customDohFallback: l10n.customDoh
        )

        return VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: l10n.sectionProfile)

            InsetGroupedCard(cornerRadius: 16) {
                VStack(spacing: 0) {
                    keyValueRow(l10n.profileMode, value: "\(s.desyncMode.label(in: appLanguage)) (\(s.chunkSize) B)")
                    InsetDivider(leadingInset: 16)
                    keyValueRow(l10n.metricDns, value: dnsValue)
                    InsetDivider(leadingInset: 16)
                    keyValueRow(l10n.profileQuicBlocking, value: s.blockQuic ? l10n.on : l10n.off)
                    InsetDivider(leadingInset: 16)
                    keyValueRow(l10n.profileOnDemand, value: s.onDemandEnabled ? l10n.on : l10n.off)
                }
            }
        }
        .transition(.opacity)
    }

    // MARK: - Actions

    private var actionsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: l10n.sectionActions)

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

                    Text(l10n.clearEngineCache)
                        .font(.body)
                        .foregroundStyle(palette.inkPrimary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.85)

                    Spacer(minLength: 8)

                    if cacheCleared {
                        HStack(spacing: 4) {
                            Image(systemName: "checkmark")
                                .font(.footnote.weight(.semibold))
                            Text(l10n.cleared)
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

    private static func displayDnsLabel(
        _ raw: String,
        dohEnabled: Bool,
        parenthesizedDoh: Bool,
        customDohFallback: String
    ) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let effective = trimmed.isEmpty ? "1.1.1.1" : trimmed
        if effective.lowercased().hasPrefix("https://") {
            if let components = URLComponents(string: effective),
               let host = components.host,
               !host.isEmpty
            {
                let formattedHost: String
                if host.contains(":") && !(host.hasPrefix("[") && host.hasSuffix("]")) {
                    formattedHost = "[\(host)]"
                } else {
                    formattedHost = host
                }
                let portSuffix = components.port.map { ":\($0)" } ?? ""
                let hostLabel = "\(formattedHost)\(portSuffix)"
                return parenthesizedDoh ? "\(hostLabel) (DoH)" : "\(hostLabel) DoH"
            }
            return customDohFallback
        }
        if dohEnabled {
            return parenthesizedDoh ? "\(effective) (DoH)" : "\(effective) DoH"
        }
        return effective
    }

    private func numericMetricRow<V: Equatable>(_ title: String, value: String, trigger: V) -> some View {
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
                .animation(reduceMotion ? nil : .easeOut(duration: 0.2), value: trigger)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .frame(minHeight: isCompactHeight ? 38 : 44)
        .padding(.horizontal, 16)
        .padding(.vertical, isCompactHeight ? 4 : 6)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(value)")
    }

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

// MARK: - Quiet Activity-Monitor Throughput Sparkline

private struct ThroughputSparkline: View {
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.appLanguage) private var appLanguage
    @Environment(\.displayScale) private var displayScale
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    let samples: [UInt64]
    let currentRateBytesPerSec: UInt64

    private static let windowCapacity = 24

    var body: some View {
        let l10n = L10n.catalog(for: appLanguage)
        let rateText = Self.formatRate(currentRateBytesPerSec)

        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(l10n.metricActivity)
                    .font(.footnote)
                    .foregroundStyle(palette.inkMuted)

                Spacer(minLength: 8)

                Text(rateText)
                    .font(.system(.footnote, design: .monospaced))
                    .monospacedDigit()
                    .foregroundStyle(palette.inkSecondary)
                    .contentTransition(.numericText())
                    .animation(reduceMotion ? nil : .easeOut(duration: 0.2), value: currentRateBytesPerSec)
                    .lineLimit(1)
            }

            GeometryReader { proxy in
                let width = max(proxy.size.width, 1)
                let height = max(proxy.size.height, 1)
                let hairline = 1.0 / max(displayScale, 1.0)
                let baselineY = height - hairline
                let maxSample = samples.max() ?? 0

                ZStack {
                    Path { path in
                        path.move(to: CGPoint(x: 0, y: baselineY))
                        path.addLine(to: CGPoint(x: width, y: baselineY))
                    }
                    .stroke(palette.border.opacity(0.65), lineWidth: hairline)

                    if maxSample > 0 {
                        let points = sparklinePoints(
                            width: width,
                            baselineY: baselineY,
                            maxSample: maxSample
                        )

                        areaPath(for: points, baselineY: baselineY)
                            .fill(
                                LinearGradient(
                                    colors: [palette.signal.opacity(0.08), palette.signal.opacity(0.0)],
                                    startPoint: .top,
                                    endPoint: .bottom
                                )
                            )

                        strokePath(for: points)
                            .stroke(
                                palette.signal,
                                style: StrokeStyle(lineWidth: 1.5, lineCap: .round, lineJoin: .round)
                            )
                    }
                }
            }
            .frame(height: 44)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(l10n.accessibilityActivity(rate: rateText))
    }

    private func sparklinePoints(
        width: CGFloat,
        baselineY: CGFloat,
        maxSample: UInt64
    ) -> [CGPoint] {
        let count = max(Self.windowCapacity, samples.count)
        let leadingZeros = max(0, count - samples.count)
        let topInset: CGFloat = 3
        let bottomInset: CGFloat = 1.5
        let plotBottom = max(topInset, baselineY - bottomInset)
        let usableHeight = max(plotBottom - topInset, 1)
        let denom = CGFloat(max(count - 1, 1))
        let peak = CGFloat(maxSample)

        var points: [CGPoint] = []
        points.reserveCapacity(count)

        for idx in 0..<count {
            let value: UInt64 = idx < leadingZeros ? 0 : samples[idx - leadingZeros]
            let x = width * (CGFloat(idx) / denom)
            let ratio = min(max(CGFloat(value) / peak, 0), 1)
            let y = plotBottom - (ratio * usableHeight)
            points.append(CGPoint(x: x, y: y))
        }
        return points
    }

    private func strokePath(for points: [CGPoint]) -> Path {
        Path { path in
            guard let first = points.first else { return }
            path.move(to: first)
            for point in points.dropFirst() {
                path.addLine(to: point)
            }
        }
    }

    private func areaPath(for points: [CGPoint], baselineY: CGFloat) -> Path {
        Path { path in
            guard let first = points.first, let last = points.last else { return }
            path.move(to: CGPoint(x: first.x, y: baselineY))
            path.addLine(to: first)
            for point in points.dropFirst() {
                path.addLine(to: point)
            }
            path.addLine(to: CGPoint(x: last.x, y: baselineY))
            path.closeSubpath()
        }
    }

    private static func formatRate(_ bytesPerSec: UInt64) -> String {
        if bytesPerSec < 1024 {
            return "\(bytesPerSec) B/s"
        }
        let kb = Double(bytesPerSec) / 1024.0
        if kb < 1024.0 {
            return kb < 10.0
                ? String(format: "%.1f KB/s", locale: Locale(identifier: "en_US_POSIX"), kb)
                : String(format: "%.0f KB/s", locale: Locale(identifier: "en_US_POSIX"), kb)
        }
        let mb = kb / 1024.0
        if mb < 1024.0 {
            return String(format: "%.1f MB/s", locale: Locale(identifier: "en_US_POSIX"), mb)
        }
        let gb = mb / 1024.0
        return String(format: "%.2f GB/s", locale: Locale(identifier: "en_US_POSIX"), gb)
    }
}

