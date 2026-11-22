import SwiftUI
import UIKit

struct TunnelView: View {
    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette

    @State private var showDiagnosticsSheet = false
    @State private var showLogsSheet = false

    private var isConnected: Bool { manager.phase == .connected }
    private var isBusy: Bool { manager.phase == .connecting || manager.phase == .disconnecting }

    private var heroBorderColor: Color {
        switch manager.phase {
        case .connected: return palette.signalBorder
        case .connecting, .disconnecting: return palette.warning.opacity(0.45)
        case .error: return palette.danger.opacity(0.55)
        case .disconnected: return palette.border
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
        case .disconnected: return palette.surfaceRaised
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

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                headerBar

                if manager.pendingReconnect {
                    reconnectBanner
                }

                heroCard

                actionStrip

                if isConnected {
                    liveTelemetrySection
                } else {
                    standbyProfileSection
                }
            }
            .padding(.horizontal, 16)
            .padding(.top, 16)
            .padding(.bottom, 24)
        }
        .scrollIndicators(.hidden)
        .sheet(isPresented: $showDiagnosticsSheet) {
            DiagnosticsSheet()
                .environmentObject(manager)
                .environment(\.vdpiPalette, palette)
                .presentationDetents([.medium, .large])
                .presentationDragIndicator(.visible)
        }
        .sheet(isPresented: $showLogsSheet) {
            EngineLogsSheet()
                .environmentObject(manager)
                .environment(\.vdpiPalette, palette)
                .presentationDetents([.medium, .large])
                .presentationDragIndicator(.visible)
        }
    }

    private var headerBar: some View {
        HStack(spacing: 10) {
            VdpiBrandMark()

            VStack(alignment: .leading, spacing: 1) {
                Text("vdpi")
                    .font(.system(size: 19, weight: .semibold))
                    .tracking(-0.4)
                    .foregroundStyle(palette.inkPrimary)
                Text("v\(manager.engineVersion) · iOS")
                    .font(.system(size: 11, weight: .medium, design: .monospaced))
                    .foregroundStyle(palette.inkMuted)
            }

            Spacer()

            StatusPill(
                text: manager.phase.label.uppercased(),
                tint: statusTint,
                background: statusBg,
                border: heroBorderColor
            )
        }
    }

    private var reconnectBanner: some View {
        HairlinePanel(
            borderColor: palette.warning.opacity(0.45),
            backgroundColor: palette.warningTint,
            cornerRadius: 12
        ) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Settings updated")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(palette.inkPrimary)
                    Text("Reload the tunnel to apply your new configuration.")
                        .font(.system(size: 12))
                        .foregroundStyle(palette.inkSecondary)
                }

                Spacer()

                Button("Apply") {
                    manager.applyChangesLive()
                }
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(palette.primaryButtonInk)
                .padding(.horizontal, 14)
                .frame(minHeight: 36)
                .background(palette.primaryButtonBg)
                .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
            }
            .padding(12)
        }
    }

    private var heroCard: some View {
        HairlinePanel(borderColor: heroBorderColor, cornerRadius: 16) {
            VStack(alignment: .leading, spacing: 16) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(isConnected ? "Tunnel Active" : "Local Anti-DPI Tunnel")
                        .font(.system(size: 26, weight: .semibold))
                        .tracking(-0.7)
                        .foregroundStyle(palette.inkPrimary)

                    if let err = manager.errorMessage, manager.phase == .error {
                        Text(err)
                            .font(.system(size: 13))
                            .foregroundStyle(palette.danger)
                            .fixedSize(horizontal: false, vertical: true)
                    } else if isConnected {
                        Text(
                            "\(VdpiFormatters.formatStageShort(stageNumber: manager.telemetry.stageNumber, label: manager.telemetry.stageLabel)) · Up \(VdpiFormatters.formatUptime(manager.telemetry.uptimeSecs))"
                        )
                        .font(.system(size: 12, weight: .medium, design: .monospaced))
                        .monospacedDigit()
                        .foregroundStyle(palette.signal)
                    } else {
                        Text("Zero-server userspace TLS desync & RFC 8484 DoH ring inside NetworkExtension.")
                            .font(.system(size: 13))
                            .foregroundStyle(palette.inkSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                PrimaryActionButton(
                    title: primaryButtonTitle,
                    isLoading: isBusy,
                    isDestructiveOutline: isConnected
                ) {
                    manager.toggleTunnel()
                }
            }
            .padding(16)
        }
        .animation(.easeInOut(duration: 0.2), value: manager.phase)
    }

    private var actionStrip: some View {
        HStack(spacing: 10) {
            GhostActionButton(title: "Diagnostics", systemImage: "stethoscope") {
                showDiagnosticsSheet = true
                if manager.doctorState.report == nil && !manager.doctorState.running {
                    manager.runDiagnostics()
                }
            }

            GhostActionButton(title: "Logs", systemImage: "terminal") {
                showLogsSheet = true
            }

            GhostActionButton(title: "Clear", systemImage: "arrow.counterclockwise") {
                manager.clearCache()
            }
        }
    }

    private var liveTelemetrySection: some View {
        let t = manager.telemetry
        let columns = [
            GridItem(.flexible(), spacing: 10),
            GridItem(.flexible(), spacing: 10),
        ]

        return HairlinePanel {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    SectionOverline(title: "Live Telemetry")
                    Spacer()
                    Text(t.dohEnabled ? "DoH · \(t.dnsAddr)" : "DNS · \(t.dnsAddr)")
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .foregroundStyle(palette.inkSecondary)
                }

                LazyVGrid(columns: columns, spacing: 10) {
                    MetricTile(label: "Upload", value: VdpiFormatters.formatBytes(t.bytesTx))
                    MetricTile(label: "Download", value: VdpiFormatters.formatBytes(t.bytesRx))
                    MetricTile(label: "Active / Total", value: "\(t.activeConnections) / \(t.totalConnections)")
                    MetricTile(label: "TLS Handshakes", value: "\(t.tlsHandshakes)")
                    MetricTile(label: "DNS Queries", value: "\(t.dnsQueries)")
                    MetricTile(label: "QUIC Fallback", value: "\(t.quicBlocked)")
                    MetricTile(label: "UDP Flows", value: "\(t.udpFlowsActive)")
                    MetricTile(label: "Learned Hosts", value: "\(t.learnedHosts)")
                }
            }
            .padding(14)
        }
        .transition(.opacity)
    }

    private var standbyProfileSection: some View {
        let s = manager.settings
        return HairlinePanel {
            VStack(alignment: .leading, spacing: 0) {
                SectionOverline(title: "Active Profile")
                    .padding(.horizontal, 14)
                    .padding(.top, 14)
                    .padding(.bottom, 10)

                HairlineRule()

                profileRow("Desync Mode", value: s.desyncMode.label)
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
        HStack {
            Text(title)
                .font(.system(size: 13))
                .foregroundStyle(palette.inkSecondary)
            Spacer()
            Text(value)
                .font(.system(size: 13, weight: .medium, design: .monospaced))
                .foregroundStyle(palette.inkPrimary)
        }
        .padding(.horizontal, 14)
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
                palette.canvas.ignoresSafeArea()

                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        if manager.doctorState.running {
                            HairlinePanel {
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
                                .padding(14)
                            }
                        } else if let report = manager.doctorState.report {
                            HairlinePanel {
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
                                    }
                                }
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
                palette.canvas.ignoresSafeArea()

                if manager.telemetry.events.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "terminal")
                            .font(.system(size: 24))
                            .foregroundStyle(palette.inkMuted)
                        Text("No engine events yet")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundStyle(palette.inkSecondary)
                        Text("Connect the tunnel or run Diagnostics to capture live events.")
                            .font(.system(size: 12))
                            .foregroundStyle(palette.inkMuted)
                            .multilineTextAlignment(.center)
                    }
                    .padding(32)
                } else {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 8) {
                            ForEach(manager.telemetry.events.reversed()) { ev in
                                VStack(alignment: .leading, spacing: 2) {
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
                                .padding(10)
                                .background(palette.surface)
                                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                                .overlay(
                                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                                        .strokeBorder(palette.border, lineWidth: 1)
                                )
                            }
                        }
                        .padding(16)
                    }
                }
            }
            .navigationTitle("Engine Logs")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(copied ? "Copied" : "Copy") {
                        UIPasteboard.general.string = formattedLogs
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
