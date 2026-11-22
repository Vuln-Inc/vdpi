import SwiftUI
import UIKit

struct TunnelView: View {
    var topInset: CGFloat = 0
    var bottomInset: CGFloat = 104

    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.scenePhase) private var scenePhase

    @State private var showDiagnosticsSheet = false
    @State private var showLogsSheet = false
    @State private var cacheSpinning = false

    private var isConnected: Bool { manager.phase == .connected }
    private var isBusy: Bool { manager.phase == .connecting || manager.phase == .disconnecting }

    private var heroBorderColor: Color {
        switch manager.phase {
        case .connected: return palette.signalBorder
        case .connecting, .disconnecting: return palette.warning.opacity(0.50)
        case .error: return palette.danger.opacity(0.55)
        case .disconnected: return palette.border
        }
    }

    private var heroRimAccent: Color? {
        switch manager.phase {
        case .connected: return palette.signal
        case .connecting, .disconnecting: return palette.warning
        case .error: return palette.danger
        case .disconnected: return nil
        }
    }

    private var heroShadowColor: Color {
        switch manager.phase {
        case .connected: return palette.signalGlow.opacity(palette.isDark ? 0.55 : 0.45)
        case .connecting, .disconnecting: return palette.warningGlow.opacity(palette.isDark ? 0.48 : 0.35)
        case .error: return palette.dangerGlow.opacity(palette.isDark ? 0.50 : 0.38)
        case .disconnected: return palette.shadowColor
        }
    }

    private var statusTint: Color {
        switch manager.phase {
        case .connected: return palette.signal
        case .connecting, .disconnecting: return palette.warning
        case .error: return palette.danger
        case .disconnected: return palette.inkMuted
        }
    }

    private var statusBg: Color {
        switch manager.phase {
        case .connected: return palette.signalTint
        case .connecting, .disconnecting: return palette.warningTint
        case .error: return palette.dangerTint
        case .disconnected: return palette.surfaceRaised.opacity(palette.isDark ? 0.72 : 0.82)
        }
    }

    private var heroTitle: String {
        switch manager.phase {
        case .connected: return "Protected"
        case .connecting: return "Connecting"
        case .disconnecting: return "Stopping"
        case .disconnected: return "Ready to Shield"
        case .error: return "Tunnel Error"
        }
    }

    private var primaryButtonTitle: String {
        switch manager.phase {
        case .disconnected, .error: return "Connect"
        case .connecting: return "Connecting..."
        case .connected: return "Disconnect"
        case .disconnecting: return "Stopping..."
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
            return report.ok ? palette.signal : palette.danger
        }
        return nil
    }

    private var logsBadgeColor: Color? {
        if manager.telemetry.events.contains(where: { $0.level.lowercased() == "error" }) {
            return palette.danger
        }
        return nil
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                headerBar

                heroCard

                if manager.pendingReconnect && manager.phase == .connected {
                    inlineReconnectCard
                        .transition(.opacity.combined(with: .scale(scale: 0.97, anchor: .top)))
                }

                if isConnected {
                    liveTelemetrySection
                } else {
                    standbyProfileSection
                }
            }
            .animation(VdpiMotion.cardShift, value: manager.phase)
            .animation(VdpiMotion.cardShift, value: manager.pendingReconnect)
            .animation(VdpiMotion.floatingHud, value: topInset)
            .padding(.horizontal, 16)
            .padding(.top, 12 + topInset)
            .padding(.bottom, bottomInset)
        }
        .scrollIndicators(.hidden)
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

    // MARK: - Floating Header

    private var headerBar: some View {
        HStack(spacing: 10) {
            HStack(spacing: 10) {
                VdpiBrandMark(isActive: isConnected)

                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("vdpi")
                        .font(.system(size: 28, weight: .bold))
                        .tracking(-0.7)
                        .foregroundStyle(palette.inkPrimary)

                    Text("v\(manager.engineVersion)")
                        .font(.system(size: 11, weight: .semibold, design: .monospaced))
                        .foregroundStyle(palette.inkSecondary)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .vdpiGlass(in: Capsule(), tier: .subtle)
                }
            }

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

                GlassCircleButton(
                    systemImage: "arrow.counterclockwise",
                    accessibilityLabel: "Clear Cache",
                    isSpinning: cacheSpinning
                ) {
                    cacheSpinning = true
                    manager.clearCache()
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.65) {
                        cacheSpinning = false
                    }
                }
            }
        }
    }

    // MARK: - Aurora Mesh-Gradient Hero Card

    private var heroCard: some View {
        let shape = RoundedRectangle(cornerRadius: 28, style: .continuous)
        let strategyText: String = isConnected
            ? VdpiFormatters.formatStageShort(
                stageNumber: manager.telemetry.stageNumber,
                label: manager.telemetry.stageLabel
            )
            : "S1 · \(manager.settings.desyncMode.label)"

        return VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 8) {
                StatusPill(
                    text: manager.phase.label.uppercased(),
                    tint: statusTint,
                    background: statusBg,
                    border: heroBorderColor,
                    isPulsing: isConnected || isBusy
                )

                Spacer(minLength: 6)

                Text(strategyText)
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .foregroundStyle(palette.inkSecondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .vdpiGlass(in: Capsule(), tier: .subtle)
            }

            VStack(alignment: .leading, spacing: 6) {
                Text(heroTitle)
                    .font(.system(size: 30, weight: .bold))
                    .tracking(-0.8)
                    .foregroundStyle(palette.inkPrimary)

                heroSubtitle
            }

            if isConnected {
                connectedThroughputBar
                    .transition(.opacity.combined(with: .scale(scale: 0.97, anchor: .top)))
            }

            PrimaryActionButton(
                title: primaryButtonTitle,
                isLoading: isBusy,
                isDestructiveOutline: isConnected
            ) {
                manager.toggleTunnel()
            }
        }
        .padding(20)
        .background(
            OrganicMeshHeroBackdrop(
                phase: manager.phase,
                isSceneActive: scenePhase == .active
            )
        )
        .clipShape(shape)
        .overlay(
            shape.strokeBorder(
                palette.specularRim(accent: heroRimAccent),
                lineWidth: 1.15
            )
        )
        .shadow(
            color: heroShadowColor,
            radius: isConnected ? 26 : 16,
            x: 0,
            y: isConnected ? 14 : 8
        )
        .animation(VdpiMotion.cardShift, value: manager.phase)
    }

    @ViewBuilder
    private var heroSubtitle: some View {
        if let err = manager.errorMessage, manager.phase == .error {
            Text(err)
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(palette.danger)
                .fixedSize(horizontal: false, vertical: true)
        } else if isConnected {
            let t = manager.telemetry
            let resolver = t.dohEnabled ? "DoH \(t.dnsAddr)" : "DNS \(t.dnsAddr)"
            Text("Up \(VdpiFormatters.formatUptime(t.uptimeSecs)) · \(resolver)")
                .font(.system(size: 13, weight: .medium, design: .monospaced))
                .monospacedDigit()
                .foregroundStyle(palette.signal)
                .contentTransition(.numericText())
                .lineLimit(1)
                .minimumScaleFactor(0.85)
        } else if manager.phase == .connecting {
            Text("Starting userspace TLS desync & RFC 8484 DoH ring...")
                .font(.system(size: 13))
                .foregroundStyle(palette.inkSecondary)
                .fixedSize(horizontal: false, vertical: true)
        } else if manager.phase == .disconnecting {
            Text("Closing local NetworkExtension tunnel...")
                .font(.system(size: 13))
                .foregroundStyle(palette.inkSecondary)
                .fixedSize(horizontal: false, vertical: true)
        } else {
            let s = manager.settings
            let resolver = s.enableDoh ? "DoH \(s.dnsAddr)" : "DNS \(s.dnsAddr)"
            Text("Zero-server TLS desync · \(resolver)")
                .font(.system(size: 13, weight: .medium, design: .monospaced))
                .foregroundStyle(palette.inkSecondary)
                .lineLimit(2)
        }
    }

    private var connectedThroughputBar: some View {
        let t = manager.telemetry
        return HStack(spacing: 0) {
            throughputColumn(
                label: "DOWNLINK",
                value: VdpiFormatters.formatBytes(t.bytesRx)
            )

            Rectangle()
                .fill(palette.border)
                .frame(width: 1, height: 26)

            throughputColumn(
                label: "UPLINK",
                value: VdpiFormatters.formatBytes(t.bytesTx)
            )

            Rectangle()
                .fill(palette.border)
                .frame(width: 1, height: 26)

            throughputColumn(
                label: "QUIC BLOCKED",
                value: "\(t.quicBlocked)"
            )
        }
        .padding(.vertical, 10)
        .padding(.horizontal, 6)
        .vdpiGlass(
            in: RoundedRectangle(cornerRadius: 16, style: .continuous),
            tier: .subtle
        )
    }

    private func throughputColumn(label: String, value: String) -> some View {
        VStack(spacing: 3) {
            Text(label)
                .font(.system(size: 9.5, weight: .semibold, design: .monospaced))
                .tracking(0.6)
                .foregroundStyle(palette.inkMuted)
                .lineLimit(1)

            Text(value)
                .font(.system(size: 14, weight: .semibold, design: .monospaced))
                .monospacedDigit()
                .foregroundStyle(palette.inkPrimary)
                .contentTransition(.numericText())
                .lineLimit(1)
                .minimumScaleFactor(0.8)
        }
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label): \(value)")
    }

    // MARK: - Persistent Home Inline Reconnect Card

    private var inlineReconnectCard: some View {
        let detail = manager.pendingChangeSummary.isEmpty
            ? "Reload the tunnel to apply your updated settings."
            : "Pending: \(manager.pendingChangeSummary)"

        return GlassPanel(
            cornerRadius: 20,
            tier: .regular,
            tint: palette.warningTint,
            borderAccent: palette.warning
        ) {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .fill(palette.warningTint)
                        .overlay(
                            Circle()
                                .strokeBorder(palette.warning.opacity(0.35), lineWidth: 1)
                        )
                        .frame(width: 34, height: 34)
                    Image(systemName: "arrow.triangle.2.circlepath")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(palette.warning)
                }
                .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 2) {
                    Text("Settings updated")
                        .font(.system(size: 13.5, weight: .semibold))
                        .foregroundStyle(palette.inkPrimary)
                    Text(detail)
                        .font(.system(size: 12))
                        .foregroundStyle(palette.inkSecondary)
                        .lineLimit(2)
                }

                Spacer(minLength: 6)

                Button {
                    VdpiHaptics.trigger(.medium)
                    manager.applyChangesLive()
                } label: {
                    Group {
                        if manager.isReloading {
                            ProgressView()
                                .progressViewStyle(.circular)
                                .tint(palette.primaryButtonInk)
                                .scaleEffect(0.78)
                        } else {
                            Text("Apply")
                                .font(.system(size: 13, weight: .semibold))
                        }
                    }
                    .foregroundStyle(palette.primaryButtonInk)
                    .padding(.horizontal, 16)
                    .frame(minWidth: 72, minHeight: 38)
                    .background(palette.primaryButtonBg)
                    .clipShape(Capsule())
                }
                .buttonStyle(VdpiPressButtonStyle(haptic: nil))
                .disabled(manager.isReloading)
            }
            .padding(14)
        }
    }

    // MARK: - Live Telemetry

    private var liveTelemetrySection: some View {
        let t = manager.telemetry
        let columns = [
            GridItem(.flexible(), spacing: 10),
            GridItem(.flexible(), spacing: 10),
        ]

        return GlassPanel(cornerRadius: 22) {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    SectionOverline(title: "Live Telemetry")
                    Spacer()
                    Text(t.dohEnabled ? "DoH · \(t.dnsAddr)" : "DNS · \(t.dnsAddr)")
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .foregroundStyle(palette.inkSecondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }

                LazyVGrid(columns: columns, spacing: 10) {
                    MetricTile(
                        label: "Upload",
                        value: VdpiFormatters.formatBytes(t.bytesTx),
                        systemImage: "arrow.up"
                    )
                    MetricTile(
                        label: "Download",
                        value: VdpiFormatters.formatBytes(t.bytesRx),
                        systemImage: "arrow.down"
                    )
                    MetricTile(
                        label: "Active / Total",
                        value: "\(t.activeConnections) / \(t.totalConnections)",
                        systemImage: "network"
                    )
                    MetricTile(
                        label: "TLS Handshakes",
                        value: "\(t.tlsHandshakes)",
                        systemImage: "lock.shield"
                    )
                    MetricTile(
                        label: "DNS Queries",
                        value: "\(t.dnsQueries)",
                        systemImage: "globe"
                    )
                    MetricTile(
                        label: "QUIC Fallback",
                        value: "\(t.quicBlocked)",
                        systemImage: "bolt.slash"
                    )
                    MetricTile(
                        label: "UDP Flows",
                        value: "\(t.udpFlowsActive)",
                        systemImage: "dot.radiowaves.left.and.right"
                    )
                    MetricTile(
                        label: "Learned Hosts",
                        value: "\(t.learnedHosts)",
                        systemImage: "cpu"
                    )
                }
                .contentTransition(.numericText())
            }
            .padding(16)
        }
        .transition(.opacity)
    }

    // MARK: - Standby Profile

    private var standbyProfileSection: some View {
        let s = manager.settings
        return GlassPanel(cornerRadius: 22) {
            VStack(alignment: .leading, spacing: 0) {
                SectionOverline(title: "Active Profile")
                    .padding(.horizontal, 16)
                    .padding(.top, 16)
                    .padding(.bottom, 12)

                HairlineRule()

                profileRow("Desync Mode", value: "\(s.desyncMode.label) (\(s.chunkSize) B)")
                HairlineRule()
                profileRow("DNS Ring", value: s.enableDoh ? "DoH (\(s.dnsAddr))" : s.dnsAddr)
                HairlineRule()
                profileRow("QUIC Fallback", value: s.blockQuic ? "Enabled (UDP/443)" : "Disabled")
                HairlineRule()
                profileRow("On-Demand", value: s.onDemandEnabled ? "Auto-Connect" : "Manual")
                HairlineRule()
                profileRow(
                    "Bypass Rules",
                    value: s.bypassDomains.isEmpty ? "Built-in LAN & Portals" : "\(s.bypassDomains.count) custom"
                )
            }
        }
        .transition(.opacity)
    }

    private func profileRow(_ title: String, value: String) -> some View {
        HStack(spacing: 12) {
            Text(title)
                .font(.system(size: 13))
                .foregroundStyle(palette.inkSecondary)
            Spacer()
            Text(value)
                .font(.system(size: 13, weight: .medium, design: .monospaced))
                .foregroundStyle(palette.inkPrimary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }
}

// MARK: - Diagnostics Sheet

private struct DiagnosticsSheet: View {
    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ZStack {
                VdpiAmbientBackdrop(phase: manager.phase)

                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        if manager.doctorState.running {
                            GlassPanel(cornerRadius: 20) {
                                HStack(spacing: 12) {
                                    ProgressView()
                                        .tint(palette.inkPrimary)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("Running live probes...")
                                            .font(.system(size: 14, weight: .semibold))
                                            .foregroundStyle(palette.inkPrimary)
                                        Text("Testing RFC 8484 DoH and TLS 1.3/1.2 ServerHello desync.")
                                            .font(.system(size: 12))
                                            .foregroundStyle(palette.inkSecondary)
                                    }
                                    Spacer()
                                }
                                .padding(16)
                            }
                        } else if let doctorError = manager.doctorState.error {
                            GlassPanel(
                                cornerRadius: 20,
                                tier: .regular,
                                tint: palette.dangerTint,
                                borderAccent: palette.danger
                            ) {
                                HStack(alignment: .top, spacing: 10) {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundStyle(palette.danger)
                                        .padding(.top, 2)
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text("Diagnostics failed")
                                            .font(.system(size: 14, weight: .semibold))
                                            .foregroundStyle(palette.inkPrimary)
                                        Text(doctorError)
                                            .font(.system(size: 12))
                                            .foregroundStyle(palette.inkSecondary)
                                            .fixedSize(horizontal: false, vertical: true)
                                    }
                                    Spacer()
                                }
                                .padding(16)
                            }
                        } else if let report = manager.doctorState.report, !report.checks.isEmpty {
                            GlassPanel(cornerRadius: 20) {
                                VStack(spacing: 0) {
                                    ForEach(Array(report.checks.enumerated()), id: \.element.id) { idx, check in
                                        if idx > 0 {
                                            HairlineRule()
                                        }
                                        HStack(alignment: .top, spacing: 12) {
                                            Image(systemName: check.passed ? "checkmark.circle.fill" : "xmark.circle.fill")
                                                .font(.system(size: 16))
                                                .foregroundStyle(check.passed ? palette.signal : palette.danger)
                                                .padding(.top, 2)

                                            VStack(alignment: .leading, spacing: 3) {
                                                HStack {
                                                    Text(check.name)
                                                        .font(.system(size: 14, weight: .semibold))
                                                        .foregroundStyle(palette.inkPrimary)
                                                    Spacer()
                                                    Text("\(check.latencyMs) ms")
                                                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                                                        .monospacedDigit()
                                                        .foregroundStyle(palette.inkMuted)
                                                }
                                                Text(check.target)
                                                    .font(.system(size: 11, design: .monospaced))
                                                    .foregroundStyle(palette.inkMuted)
                                                Text(check.detail)
                                                    .font(.system(size: 12))
                                                    .foregroundStyle(palette.inkSecondary)
                                                    .fixedSize(horizontal: false, vertical: true)
                                            }
                                        }
                                        .padding(14)
                                        .accessibilityElement(children: .combine)
                                        .accessibilityLabel(
                                            "\(check.name), \(check.passed ? "Passed" : "Failed"), \(check.latencyMs) milliseconds, \(check.detail)"
                                        )
                                    }
                                }
                            }
                        } else {
                            GlassPanel(cornerRadius: 20) {
                                Text("Tap Run Diagnostics to verify live DoH and TLS desync probes.")
                                    .font(.system(size: 13))
                                    .foregroundStyle(palette.inkSecondary)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding(16)
                            }
                        }

                        PrimaryActionButton(
                            title: manager.doctorState.running ? "Testing..." : "Run Diagnostics Again",
                            isLoading: manager.doctorState.running,
                            isDestructiveOutline: false
                        ) {
                            manager.runDiagnostics()
                        }
                    }
                    .padding(16)
                }
                .scrollIndicators(.hidden)
            }
            .navigationTitle("Diagnostics")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                        .foregroundStyle(palette.inkPrimary)
                }
            }
        }
    }
}

// MARK: - Engine Logs Sheet

private struct EngineLogsSheet: View {
    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    private var formattedLogs: String {
        manager.telemetry.events.map { ev in
            "[\(VdpiFormatters.formatEventTime(ev.tsMs))] [\(ev.level.uppercased())] [\(ev.tag)] \(ev.message)"
        }.joined(separator: "\n")
    }

    var body: some View {
        NavigationStack {
            ZStack {
                VdpiAmbientBackdrop(phase: manager.phase)

                if manager.telemetry.events.isEmpty {
                    VStack(spacing: 10) {
                        Image(systemName: "terminal")
                            .font(.system(size: 26))
                            .foregroundStyle(palette.inkMuted)
                        Text("No engine events yet")
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundStyle(palette.inkPrimary)
                        Text("Connect the tunnel or run Diagnostics to capture live events.")
                            .font(.system(size: 12.5))
                            .foregroundStyle(palette.inkSecondary)
                            .multilineTextAlignment(.center)
                    }
                    .padding(32)
                } else {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 8) {
                            ForEach(manager.telemetry.events.reversed()) { ev in
                                GlassPanel(cornerRadius: 14, tier: .subtle) {
                                    VStack(alignment: .leading, spacing: 3) {
                                        HStack(spacing: 6) {
                                            Text(VdpiFormatters.formatEventTime(ev.tsMs))
                                                .font(.system(size: 11, design: .monospaced))
                                                .foregroundStyle(palette.inkMuted)
                                            Text(ev.tag.uppercased())
                                                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                                                .foregroundStyle(levelColor(ev.level))
                                        }
                                        Text(ev.message)
                                            .font(.system(size: 12, design: .monospaced))
                                            .foregroundStyle(palette.inkPrimary)
                                            .fixedSize(horizontal: false, vertical: true)
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding(12)
                                }
                            }
                        }
                        .padding(16)
                    }
                    .scrollIndicators(.hidden)
                }
            }
            .navigationTitle("Engine Logs")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(copied ? "Copied" : "Copy") {
                        UIPasteboard.general.string = formattedLogs
                        VdpiHaptics.trigger(.success)
                        copied = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.8) {
                            copied = false
                        }
                    }
                    .disabled(manager.telemetry.events.isEmpty)
                    .foregroundStyle(palette.inkPrimary)
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                        .foregroundStyle(palette.inkPrimary)
                }
            }
        }
    }

    private func levelColor(_ level: String) -> Color {
        switch level.lowercased() {
        case "error": return palette.danger
        case "warn": return palette.warning
        case "info": return palette.signal
        default: return palette.inkMuted
        }
    }
}
