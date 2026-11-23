import SwiftUI
import UIKit

struct TunnelView: View {
    var topInset: CGFloat = 0
    var bottomInset: CGFloat = 104
    var showInlineReconnect: Bool = true

    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    @State private var showDiagnosticsSheet = false
    @State private var showLogsSheet = false
    @State private var cacheCleared = false
    @State private var cacheFeedbackTask: Task<Void, Never>?

    private var isConnected: Bool { manager.phase == .connected }
    private var isBusy: Bool { manager.phase == .connecting || manager.phase == .disconnecting }

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
        case .connecting: return "Connecting..."
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

    var body: some View {
        ScrollView {
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
            .animation(reduceMotion ? nil : VdpiMotion.cardShift, value: manager.phase)
            .animation(reduceMotion ? nil : VdpiMotion.cardShift, value: manager.pendingReconnect)
            .animation(reduceMotion ? nil : VdpiMotion.cardShift, value: showInlineReconnect)
            .animation(reduceMotion ? nil : VdpiMotion.floatingHud, value: topInset)
            .padding(.horizontal, 16)
            .padding(.top, 12 + topInset)
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

    // MARK: - Header

    private var headerBar: some View {
        HStack(alignment: .center, spacing: 12) {
            Text("vdpi")
                .font(.largeTitle.bold())
                .tracking(-0.6)
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
            VStack(spacing: 0) {
                StatusDisc(phase: manager.phase)

                Text(heroTitle)
                    .font(.title2.bold())
                    .foregroundStyle(palette.inkPrimary)
                    .multilineTextAlignment(.center)
                    .padding(.top, 14)

                heroSubtitle
                    .padding(.top, 4)

                PrimaryActionButton(
                    title: primaryButtonTitle,
                    isLoading: isBusy,
                    isDestructiveOutline: isConnected || isBusy
                ) {
                    manager.toggleTunnel()
                }
                .padding(.top, 20)
            }
            .frame(maxWidth: .infinity)
            .padding(20)
        }
    }

    @ViewBuilder
    private var heroSubtitle: some View {
        if let err = manager.errorMessage, manager.phase == .error {
            Text(err)
                .font(.subheadline)
                .foregroundStyle(palette.danger)
                .multilineTextAlignment(.center)
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
                .lineLimit(1)
                .minimumScaleFactor(0.85)
        } else if manager.phase == .connecting {
            Text("Establishing local tunnel...")
                .font(.subheadline)
                .foregroundStyle(palette.inkSecondary)
                .multilineTextAlignment(.center)
                .lineLimit(1)
        } else if manager.phase == .disconnecting {
            Text("Closing local tunnel...")
                .font(.subheadline)
                .foregroundStyle(palette.inkSecondary)
                .multilineTextAlignment(.center)
                .lineLimit(1)
        } else {
            Text("Local anti-DPI tunnel ready")
                .font(.subheadline)
                .foregroundStyle(palette.inkSecondary)
                .multilineTextAlignment(.center)
                .lineLimit(1)
        }
    }

    // MARK: - Persistent Home Inline Reconnect Row

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

    // MARK: - Connection Telemetry Section

    private var connectionSection: some View {
        let t = manager.telemetry
        let dnsValue = t.dohEnabled ? "\(t.dnsAddr) (DoH)" : t.dnsAddr

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
                    keyValueRow("QUIC Blocked", value: "\(t.quicBlocked)")
                }
            }
        }
        .transition(.opacity)
    }

    // MARK: - Standby Profile Section

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

    // MARK: - Actions Section

    private var actionsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "Actions")

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
                    .padding(.vertical, 6)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
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
        .frame(minHeight: 44)
        .padding(.horizontal, 16)
        .padding(.vertical, 6)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(value)")
    }

    private func triggerClearCache() {
        VdpiHaptics.trigger(.light)
        manager.clearCache()
        cacheFeedbackTask?.cancel()
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
        ZStack {
            Circle()
                .fill(discFill)
                .frame(width: 68, height: 68)

            Image(systemName: symbolName)
                .font(.system(size: 28, weight: .semibold))
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

// MARK: - Sheet Inset Card (Elevated Dark Sheet Contrast)

private struct SheetInsetCard<Content: View>: View {
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.colorSchemeContrast) private var colorSchemeContrast

    var cornerRadius: CGFloat = 16
    @ViewBuilder let content: () -> Content

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        let fillColor = palette.isDark ? palette.surfaceRaised : palette.surface
        content()
            .background(shape.fill(fillColor))
            .clipShape(shape)
            .overlay {
                if colorSchemeContrast == .increased {
                    shape
                        .strokeBorder(palette.borderStrong, lineWidth: 1.0)
                        .allowsHitTesting(false)
                }
            }
    }
}

// MARK: - Diagnostics Sheet

private struct DiagnosticsSheet: View {
    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.dismiss) private var dismiss

    private var sheetBackground: Color {
        palette.isDark ? palette.surface : palette.canvas
    }

    var body: some View {
        NavigationStack {
            ZStack {
                sheetBackground
                    .ignoresSafeArea()

                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        SectionHeader(title: "Checks")

                        if manager.doctorState.running {
                            SheetInsetCard(cornerRadius: 16) {
                                HStack(spacing: 12) {
                                    ProgressView()
                                        .progressViewStyle(.circular)
                                        .tint(palette.inkSecondary)

                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("Running Diagnostics")
                                            .font(.body)
                                            .foregroundStyle(palette.inkPrimary)

                                        Text("Testing DNS, DoH, TLS, and QUIC paths.")
                                            .font(.footnote)
                                            .foregroundStyle(palette.inkSecondary)
                                    }

                                    Spacer(minLength: 8)
                                }
                                .frame(minHeight: 56)
                                .padding(.horizontal, 16)
                                .padding(.vertical, 10)
                            }
                        } else if let doctorError = manager.doctorState.error {
                            SheetInsetCard(cornerRadius: 16) {
                                HStack(alignment: .top, spacing: 12) {
                                    Image(systemName: "xmark.circle.fill")
                                        .font(.title3)
                                        .foregroundStyle(palette.danger)
                                        .padding(.top, 1)

                                    VStack(alignment: .leading, spacing: 3) {
                                        Text("Diagnostics Failed")
                                            .font(.body)
                                            .foregroundStyle(palette.inkPrimary)

                                        Text(doctorError)
                                            .font(.footnote)
                                            .foregroundStyle(palette.inkSecondary)
                                            .fixedSize(horizontal: false, vertical: true)
                                    }

                                    Spacer(minLength: 8)
                                }
                                .frame(minHeight: 56)
                                .padding(.horizontal, 16)
                                .padding(.vertical, 12)
                            }
                        } else if let report = manager.doctorState.report, !report.checks.isEmpty {
                            SheetInsetCard(cornerRadius: 16) {
                                VStack(spacing: 0) {
                                    ForEach(Array(report.checks.enumerated()), id: \.element.id) { idx, check in
                                        if idx > 0 {
                                            InsetDivider(leadingInset: 48)
                                        }
                                        diagnosticCheckRow(check)
                                    }
                                }
                            }

                            SectionFooter(text: summaryFooter(for: report))
                        } else {
                            SheetInsetCard(cornerRadius: 16) {
                                Text("Tap Re-run to verify live DNS, DoH, and TLS desync probes.")
                                    .font(.subheadline)
                                    .foregroundStyle(palette.inkSecondary)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding(16)
                            }
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.top, 16)
                    .padding(.bottom, 24)
                }
                .scrollIndicators(.hidden)
            }
            .navigationTitle("Diagnostics")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Re-run") {
                        VdpiHaptics.trigger(.light)
                        manager.runDiagnostics()
                    }
                    .foregroundStyle(manager.doctorState.running ? palette.inkMuted : palette.accent)
                    .disabled(manager.doctorState.running)
                }

                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") {
                        dismiss()
                    }
                    .fontWeight(.semibold)
                    .foregroundStyle(palette.accent)
                }
            }
        }
    }

    private func diagnosticCheckRow(_ check: DoctorCheck) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: check.passed ? "checkmark.circle.fill" : "xmark.circle.fill")
                .font(.title3)
                .foregroundStyle(check.passed ? palette.signal : palette.danger)
                .padding(.top, 1)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                Text(check.name)
                    .font(.body)
                    .foregroundStyle(palette.inkPrimary)

                if !check.detail.isEmpty {
                    Text(check.detail)
                        .font(.footnote)
                        .foregroundStyle(palette.inkSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                if !check.target.isEmpty {
                    Text(check.target)
                        .font(.caption)
                        .foregroundStyle(palette.inkMuted)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }

            Spacer(minLength: 8)

            Text("\(check.latencyMs) ms")
                .font(.subheadline)
                .monospacedDigit()
                .foregroundStyle(palette.inkSecondary)
                .padding(.top, 2)
        }
        .frame(minHeight: 48)
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(
            "\(check.name), \(check.passed ? "Passed" : "Failed"), \(check.latencyMs) milliseconds, \(check.detail)"
        )
    }

    private func summaryFooter(for report: DoctorReport) -> String {
        let failedCount = report.checks.filter { !$0.passed }.count
        if failedCount == 0 {
            return "All \(report.checks.count) checks passed."
        }
        let noun = failedCount == 1 ? "issue" : "issues"
        return "\(failedCount) \(noun) detected - check DNS or network settings."
    }
}

// MARK: - Engine Logs Sheet

private struct EngineLogsSheet: View {
    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.dismiss) private var dismiss

    @State private var copied = false
    @State private var copyFeedbackTask: Task<Void, Never>?

    private var formattedLogs: String {
        manager.telemetry.events.map { ev in
            "[\(VdpiFormatters.formatEventTime(ev.tsMs))] \(severityPrefix(ev.level)) [\(ev.tag)] \(ev.message)"
        }.joined(separator: "\n")
    }

    private var sheetBackground: Color {
        palette.isDark ? palette.surface : palette.canvas
    }

    private var logWellBackground: Color {
        palette.isDark ? palette.canvas : palette.surface
    }

    var body: some View {
        NavigationStack {
            ZStack {
                sheetBackground
                    .ignoresSafeArea()

                if manager.telemetry.events.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "terminal")
                            .font(.title)
                            .foregroundStyle(palette.inkMuted)
                            .accessibilityHidden(true)

                        Text("No Engine Logs Yet")
                            .font(.headline)
                            .foregroundStyle(palette.inkPrimary)

                        Text("Connect the tunnel to record activity.")
                            .font(.subheadline)
                            .foregroundStyle(palette.inkSecondary)
                            .multilineTextAlignment(.center)
                    }
                    .padding(32)
                } else {
                    ScrollViewReader { proxy in
                        ScrollView {
                            LazyVStack(alignment: .leading, spacing: 6) {
                                ForEach(manager.telemetry.events) { ev in
                                    logLineView(ev)
                                        .id(ev.id)
                                }

                                Color.clear
                                    .frame(height: 1)
                                    .id("engine-logs-bottom")
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(12)
                            .textSelection(.enabled)
                        }
                        .background(
                            RoundedRectangle(cornerRadius: 14, style: .continuous)
                                .fill(logWellBackground)
                        )
                        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .padding(16)
                        .onAppear {
                            proxy.scrollTo("engine-logs-bottom", anchor: .bottom)
                        }
                        .vdpiOnChange(of: manager.telemetry.events.last?.id) { _ in
                            if reduceMotion {
                                proxy.scrollTo("engine-logs-bottom", anchor: .bottom)
                            } else {
                                withAnimation(.easeOut(duration: 0.2)) {
                                    proxy.scrollTo("engine-logs-bottom", anchor: .bottom)
                                }
                            }
                        }
                    }
                }
            }
            .onDisappear {
                copyFeedbackTask?.cancel()
            }
            .navigationTitle("Engine Logs")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItemGroup(placement: .navigationBarLeading) {
                    Button {
                        UIPasteboard.general.string = formattedLogs
                        VdpiHaptics.trigger(.success)
                        copyFeedbackTask?.cancel()
                        copied = true
                        copyFeedbackTask = Task { @MainActor in
                            try? await Task.sleep(nanoseconds: 1_800_000_000)
                            guard !Task.isCancelled else { return }
                            copied = false
                        }
                    } label: {
                        Text(copied ? "Copied" : "Copy")
                    }
                    .foregroundStyle(
                        manager.telemetry.events.isEmpty ? palette.inkMuted : palette.accent
                    )
                    .disabled(manager.telemetry.events.isEmpty)

                    ShareLink(item: formattedLogs) {
                        Image(systemName: "square.and.arrow.up")
                    }
                    .foregroundStyle(
                        manager.telemetry.events.isEmpty ? palette.inkMuted : palette.accent
                    )
                    .disabled(manager.telemetry.events.isEmpty)
                    .accessibilityLabel("Share Engine Logs")
                }

                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") {
                        dismiss()
                    }
                    .fontWeight(.semibold)
                    .foregroundStyle(palette.accent)
                }
            }
        }
    }

    private func logLineView(_ ev: EngineEvent) -> some View {
        let timestamp = Text(VdpiFormatters.formatEventTime(ev.tsMs) + " ")
            .foregroundColor(palette.inkMuted)
        let prefix = Text(severityPrefix(ev.level) + " ")
            .foregroundColor(levelColor(ev.level))
        let tag = Text("[\(ev.tag)] ")
            .foregroundColor(palette.inkMuted)
        let message = Text(ev.message)
            .foregroundColor(palette.inkPrimary)

        return Text("\(timestamp)\(prefix)\(tag)\(message)")
            .font(.system(.caption, design: .monospaced))
            .monospacedDigit()
            .lineSpacing(4)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func severityPrefix(_ level: String) -> String {
        switch level.lowercased() {
        case "error", "err": return "[ERR]"
        case "warn", "warning": return "[WARN]"
        case "info": return "[INFO]"
        default: return "[\(level.uppercased())]"
        }
    }

    private func levelColor(_ level: String) -> Color {
        switch level.lowercased() {
        case "error", "err": return palette.danger
        case "warn", "warning": return palette.warning
        default: return palette.inkSecondary
        }
    }
}
