import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

// MARK: - Diagnostics Sheet

struct DiagnosticsSheet: View {
    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.appLanguage) private var appLanguage
    @Environment(\.dismiss) private var dismiss

    private var l10n: L10n.Catalog {
        L10n.catalog(for: appLanguage)
    }

    private var sheetBackground: Color {
        palette.isDark ? palette.surface : palette.canvas
    }

    // MARK: - Body

    var body: some View {
        NavigationStack {
            ZStack {
                sheetBackground
                    .ignoresSafeArea()

                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        if manager.doctorState.running {
                            SectionHeader(title: l10n.diagnosticsSectionChecks)
                            runningCard
                        } else if let doctorError = manager.doctorState.error {
                            SectionHeader(title: l10n.diagnosticsSectionChecks)
                            errorCard(doctorError)
                        } else if let report = manager.doctorState.report, !report.checks.isEmpty {
                            summaryStrip(for: report)

                            SectionHeader(title: l10n.diagnosticsSectionChecks)
                                .padding(.top, 4)

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

                            if let footer = summaryFooter(for: report) {
                                SectionFooter(text: footer)
                            }
                        } else {
                            SectionHeader(title: l10n.diagnosticsSectionChecks)
                            emptyCard
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.top, 16)
                    .padding(.bottom, 24)
                }
                .scrollIndicators(.hidden)
            }
            .navigationTitle(l10n.diagnosticsTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItemGroup(placement: .navigationBarLeading) {
                    Button(l10n.rerunButton) {
                        VdpiHaptics.trigger(.light)
                        manager.runDiagnostics()
                    }
                    .foregroundStyle(manager.doctorState.running ? palette.inkMuted : palette.accent)
                    .disabled(manager.doctorState.running)

                    ShareLink(item: manager.formattedDiagnosticsReport()) {
                        Image(systemName: "square.and.arrow.up")
                    }
                    .foregroundStyle(canShareReport ? palette.accent : palette.inkMuted)
                    .disabled(!canShareReport)
                    .accessibilityLabel(l10n.accessibilityShareDiagnostics)
                }

                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(l10n.done) {
                        dismiss()
                    }
                    .fontWeight(.semibold)
                    .foregroundStyle(palette.accent)
                }
            }
        }
    }

    private var canShareReport: Bool {
        guard !manager.doctorState.running,
              let report = manager.doctorState.report
        else { return false }
        return !report.checks.isEmpty
    }

    // MARK: - State Cards

    private var runningCard: some View {
        SheetInsetCard(cornerRadius: 16) {
            HStack(spacing: 12) {
                ProgressView()
                    .progressViewStyle(.circular)
                    .tint(palette.inkSecondary)

                VStack(alignment: .leading, spacing: 2) {
                    Text(l10n.runningDiagnosticsTitle)
                        .font(.body)
                        .foregroundStyle(palette.inkPrimary)

                    Text(l10n.runningDiagnosticsSubtitle)
                        .font(.footnote)
                        .foregroundStyle(palette.inkSecondary)
                }

                Spacer(minLength: 8)
            }
            .frame(minHeight: 56)
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
        }
    }

    private func errorCard(_ message: String) -> some View {
        SheetInsetCard(cornerRadius: 16) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "xmark.circle.fill")
                    .font(.title3)
                    .foregroundStyle(palette.danger)
                    .padding(.top, 1)

                VStack(alignment: .leading, spacing: 3) {
                    Text(l10n.diagnosticsFailedTitle)
                        .font(.body)
                        .foregroundStyle(palette.inkPrimary)

                    Text(message)
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
    }

    private var emptyCard: some View {
        SheetInsetCard(cornerRadius: 16) {
            Text(l10n.diagnosticsEmptyMessage)
                .font(.subheadline)
                .foregroundStyle(palette.inkSecondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(16)
        }
    }

    // MARK: - Check Row & Summary

    private func diagnosticCheckRow(_ check: DoctorCheck) -> some View {
        let displayName = l10n.doctorCheckName(check.name)

        return HStack(alignment: .top, spacing: 12) {
            Image(systemName: check.passed ? "checkmark.circle.fill" : "xmark.circle.fill")
                .font(.title3)
                .foregroundStyle(check.passed ? palette.signal : palette.danger)
                .padding(.top, 1)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                Text(displayName)
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
            l10n.diagnosticsCheckAccessibility(
                name: displayName,
                passed: check.passed,
                latencyMs: check.latencyMs,
                detail: check.detail
            )
        )
    }

    private func summaryStrip(for report: DoctorReport) -> some View {
        let total = report.checks.count
        let passed = report.checks.filter(\.passed).count
        let failed = total - passed
        let allPassed = failed == 0
        let statusColor: Color = allPassed ? palette.signal : (passed == 0 ? palette.danger : palette.warning)
        let title = allPassed
            ? l10n.diagnosticsAllPassed(total: total)
            : l10n.diagnosticsPartialPassed(passed: passed, total: total)

        return SheetInsetCard(cornerRadius: 14) {
            HStack(spacing: 10) {
                Image(systemName: allPassed ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .font(.body.weight(.semibold))
                    .foregroundStyle(statusColor)
                    .accessibilityHidden(true)

                Text(title)
                    .font(.subheadline.weight(.semibold))
                    .monospacedDigit()
                    .foregroundStyle(palette.inkPrimary)

                Spacer(minLength: 8)

                Text(allPassed ? l10n.diagnosticsHealthy : l10n.diagnosticsFailedCount(failed))
                    .font(.footnote.weight(.medium))
                    .monospacedDigit()
                    .foregroundStyle(allPassed ? palette.signal : palette.danger)
            }
            .frame(minHeight: 44)
            .padding(.horizontal, 16)
            .padding(.vertical, 6)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(
            l10n.accessibilityDiagnosticsSummary(passed: passed, total: total, failed: failed)
        )
    }

    private func summaryFooter(for report: DoctorReport) -> String? {
        let failedCount = report.checks.filter { !$0.passed }.count
        guard failedCount > 0 else { return nil }
        return l10n.diagnosticsIssuesFooter(failedCount: failedCount)
    }
}

// MARK: - Engine Logs Sheet

struct EngineLogsSheet: View {
    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.appLanguage) private var appLanguage
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.dismiss) private var dismiss

    @State private var copied = false
    @State private var copyFeedbackTask: Task<Void, Never>?

    private var l10n: L10n.Catalog {
        L10n.catalog(for: appLanguage)
    }

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

    // MARK: - Body

    var body: some View {
        NavigationStack {
            ZStack {
                sheetBackground
                    .ignoresSafeArea()

                if manager.telemetry.events.isEmpty {
                    emptyStateView
                } else {
                    logStreamView
                }
            }
            .onDisappear {
                copyFeedbackTask?.cancel()
            }
            .navigationTitle(l10n.engineLogsTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItemGroup(placement: .navigationBarLeading) {
                    Button {
                        copyLogsToClipboard()
                    } label: {
                        Image(systemName: copied ? "checkmark" : "doc.on.doc")
                    }
                    .foregroundStyle(
                        manager.telemetry.events.isEmpty ? palette.inkMuted : palette.accent
                    )
                    .disabled(manager.telemetry.events.isEmpty)
                    .accessibilityLabel(copied ? l10n.accessibilityCopiedLogs : l10n.accessibilityCopyLogs)

                    ShareLink(item: formattedLogs) {
                        Image(systemName: "square.and.arrow.up")
                    }
                    .foregroundStyle(
                        manager.telemetry.events.isEmpty ? palette.inkMuted : palette.accent
                    )
                    .disabled(manager.telemetry.events.isEmpty)
                    .accessibilityLabel(l10n.accessibilityShareLogs)
                }

                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(l10n.done) {
                        dismiss()
                    }
                    .fontWeight(.semibold)
                    .foregroundStyle(palette.accent)
                }
            }
        }
    }

    // MARK: - Log Content

    private var emptyStateView: some View {
        VStack(spacing: 8) {
            Image(systemName: "terminal")
                .font(.title)
                .foregroundStyle(palette.inkMuted)
                .accessibilityHidden(true)

            Text(l10n.noEngineLogsTitle)
                .font(.headline)
                .foregroundStyle(palette.inkPrimary)

            Text(l10n.noEngineLogsSubtitle)
                .font(.subheadline)
                .foregroundStyle(palette.inkSecondary)
                .multilineTextAlignment(.center)
        }
        .padding(32)
    }

    private var logStreamView: some View {
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

    // MARK: - Log Row & Formatting

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

    // MARK: - Export Actions

    private func copyLogsToClipboard() {
        #if canImport(UIKit)
        UIPasteboard.general.string = formattedLogs
        #endif
        VdpiHaptics.trigger(.success)
        copyFeedbackTask?.cancel()
        copied = true
        copyFeedbackTask = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 1_800_000_000)
            guard !Task.isCancelled else { return }
            copied = false
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
