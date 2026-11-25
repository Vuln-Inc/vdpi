import SwiftUI
import UniformTypeIdentifiers

struct SettingsView: View {
    var topInset: CGFloat = 0
    var bottomInset: CGFloat = 104

    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.colorSchemeContrast) private var colorSchemeContrast
    @Environment(\.verticalSizeClass) private var verticalSizeClass
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass

    // MARK: - Types & Constants

    private static let githubRepositoryURL = URL(string: "https://github.com/Vuln-Inc/vdpi")!

    private enum Field: Hashable {
        case dns
        case bypass
    }

    private struct DnsPreset: Identifiable {
        let label: String
        let value: String
        var id: String { value }
    }

    private let dnsPresets: [DnsPreset] = [
        DnsPreset(label: "Cloudflare", value: "1.1.1.1"),
        DnsPreset(label: "Google", value: "8.8.8.8"),
        DnsPreset(label: "AdGuard", value: "94.140.14.140"),
        DnsPreset(label: "Quad9", value: "9.9.9.9"),
    ]

    // MARK: - Local State

    @State private var dnsDraft: String = ""
    @State private var dnsError: String?
    @State private var bypassDraft: String = ""
    @State private var bypassError: String?
    @State private var showResetConfirm = false
    @State private var showSettingsExporter = false
    @State private var exportDocument = VdpiSettingsDocument()
    @State private var showSettingsImporter = false
    @FocusState private var focusedField: Field?

    // MARK: - Derived State

    private func isPresetDns(_ addr: String) -> Bool {
        dnsPresets.contains { $0.value.caseInsensitiveCompare(addr) == .orderedSame }
    }

    private func draftValue(for dnsAddr: String) -> String {
        isPresetDns(dnsAddr) ? "" : dnsAddr
    }

    private var isCustomDnsActive: Bool {
        let current = manager.settings.dnsAddr
        guard !isPresetDns(current) else { return false }
        let trimmed = dnsDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.caseInsensitiveCompare(current) == .orderedSame
    }

    private var canApplyDns: Bool {
        let trimmed = dnsDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
        return trimmed.caseInsensitiveCompare(manager.settings.dnsAddr) != .orderedSame
    }

    private var canAddBypass: Bool {
        !bypassDraft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private var isWideLayout: Bool {
        verticalSizeClass == .compact || horizontalSizeClass == .regular
    }

    private var isCompactHeight: Bool {
        verticalSizeClass == .compact
    }

    // MARK: - Body

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: isCompactHeight ? 20 : 24) {
                headerBar

                desyncSection
                dnsSection
                tunnelSection
                bypassDomainsSection
                appearanceSection
                backupSection
                updatesSection
                resetSection
                aboutSection
                versionFooter
            }
            .animation(reduceMotion ? nil : VdpiMotion.floatingHud, value: topInset)
            .animation(reduceMotion ? nil : VdpiMotion.floatingHud, value: focusedField != nil)
            .frame(maxWidth: isWideLayout ? 680 : .infinity, alignment: .leading)
            .padding(.horizontal, 16)
            .padding(.top, (isCompactHeight ? 4 : 12) + topInset)
            .padding(.bottom, bottomInset)
            .frame(maxWidth: .infinity)
        }
        .scrollIndicators(.hidden)
        .scrollDismissesKeyboard(.interactively)
        .onAppear {
            dnsDraft = draftValue(for: manager.settings.dnsAddr)
        }
        .vdpiOnChange(of: manager.settings.dnsAddr) { newDns in
            let expected = draftValue(for: newDns)
            if focusedField != .dns && dnsDraft != expected {
                dnsDraft = expected
                dnsError = nil
            }
        }
        .vdpiOnChange(of: dnsDraft) { _ in
            if dnsError != nil {
                dnsError = nil
            }
        }
        .vdpiOnChange(of: bypassDraft) { _ in
            if bypassError != nil {
                bypassError = nil
            }
        }
        .confirmationDialog(
            "Reset all tunnel settings to defaults?",
            isPresented: $showResetConfirm,
            titleVisibility: .visible
        ) {
            Button("Reset to Defaults", role: .destructive) {
                VdpiHaptics.trigger(.warning)
                focusedField = nil
                manager.resetSettings()
                dnsDraft = draftValue(for: manager.settings.dnsAddr)
                dnsError = nil
                bypassError = nil
            }
            Button("Cancel", role: .cancel) {}
        }
        .fileExporter(
            isPresented: $showSettingsExporter,
            document: exportDocument,
            contentType: .json,
            defaultFilename: "vdpi-settings.json"
        ) { result in
            switch result {
            case .success:
                VdpiHaptics.trigger(.success)
                manager.showToast("Exported settings")
            case .failure(let error):
                let nsError = error as NSError
                if nsError.domain == NSCocoaErrorDomain && nsError.code == NSUserCancelledError {
                    return
                }
                VdpiHaptics.trigger(.warning)
                manager.showToast("Export failed")
            }
        }
        .fileImporter(
            isPresented: $showSettingsImporter,
            allowedContentTypes: [.json, .plainText],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                guard let url = urls.first else { return }
                importSettings(from: url)
            case .failure(let error):
                let nsError = error as NSError
                if nsError.domain == NSCocoaErrorDomain && nsError.code == NSUserCancelledError {
                    return
                }
                VdpiHaptics.trigger(.warning)
                manager.showToast("Import failed")
            }
        }
    }

    // MARK: - Header

    private var headerBar: some View {
        HStack(alignment: .center, spacing: 12) {
            Text("Settings")
                .font(.largeTitle.bold())
                .foregroundStyle(palette.inkPrimary)
                .accessibilityAddTraits(.isHeader)

            Spacer(minLength: 8)

            if focusedField != nil {
                GlassCircleButton(
                    systemImage: "keyboard.chevron.compact.down",
                    accessibilityLabel: "Dismiss keyboard"
                ) {
                    focusedField = nil
                }
                .transition(
                    reduceMotion
                        ? .opacity
                        : .scale(scale: 0.85).combined(with: .opacity)
                )
            }
        }
        .frame(minHeight: 44)
    }

    // MARK: - Desync Engine

    private var desyncSection: some View {
        let chunkSize = manager.settings.clampedChunkSize

        return VStack(alignment: .leading, spacing: 7) {
            SectionHeader("Desync Engine")

            InsetGroupedCard(cornerRadius: 16) {
                VStack(spacing: 0) {
                    ForEach(Array(DesyncMode.allCases.enumerated()), id: \.element.id) { idx, mode in
                        if idx > 0 {
                            InsetDivider(leadingInset: 16)
                        }
                        let selected = manager.settings.desyncMode == mode
                        Button {
                            guard !selected else { return }
                            VdpiHaptics.trigger(.selection)
                            withAnimation(reduceMotion ? nil : VdpiMotion.cardShift) {
                                manager.updateSettings { $0.desyncMode = mode }
                            }
                        } label: {
                            HStack(spacing: 12) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(mode.label)
                                        .font(.body)
                                        .foregroundStyle(palette.inkPrimary)
                                    Text(mode.subtitle)
                                        .font(.footnote)
                                        .foregroundStyle(palette.inkSecondary)
                                        .lineLimit(2)
                                        .fixedSize(horizontal: false, vertical: true)
                                }

                                Spacer(minLength: 8)

                                if selected {
                                    Image(systemName: "checkmark")
                                        .font(.body.weight(.semibold))
                                        .foregroundStyle(palette.accent)
                                        .accessibilityHidden(true)
                                }
                            }
                            .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                            .padding(.horizontal, 16)
                            .padding(.vertical, 10)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(SettingsRowButtonStyle(highlightColor: palette.surfaceRaised))
                        .accessibilityAddTraits(selected ? .isSelected : [])
                    }

                    InsetDivider(leadingInset: 16)

                    HStack(spacing: 12) {
                        Text("Chunk Size")
                            .font(.body)
                            .foregroundStyle(palette.inkPrimary)
                            .fixedSize(horizontal: false, vertical: true)

                        Spacer(minLength: 8)

                        HStack(spacing: 0) {
                            Button {
                                VdpiHaptics.trigger(.light)
                                withAnimation(reduceMotion ? nil : VdpiMotion.cardShift) {
                                    manager.updateSettings { $0.chunkSize = max(1, $0.clampedChunkSize - 1) }
                                }
                            } label: {
                                Image(systemName: "minus")
                                    .font(.subheadline.weight(.semibold))
                                    .foregroundStyle(
                                        chunkSize <= 1 ? palette.inkMuted : palette.inkPrimary
                                    )
                                    .frame(minWidth: 44, minHeight: 44)
                                    .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .disabled(chunkSize <= 1)
                            .accessibilityLabel("Decrease chunk size")

                            Text("\(chunkSize) B")
                                .font(.subheadline.weight(.semibold))
                                .monospacedDigit()
                                .foregroundStyle(palette.inkPrimary)
                                .contentTransition(.numericText())
                                .frame(minWidth: 44)
                                .multilineTextAlignment(.center)
                                .accessibilityLabel("Chunk size \(chunkSize) bytes")

                            Button {
                                VdpiHaptics.trigger(.light)
                                withAnimation(reduceMotion ? nil : VdpiMotion.cardShift) {
                                    manager.updateSettings { $0.chunkSize = min(64, $0.clampedChunkSize + 1) }
                                }
                            } label: {
                                Image(systemName: "plus")
                                    .font(.subheadline.weight(.semibold))
                                    .foregroundStyle(
                                        chunkSize >= 64 ? palette.inkMuted : palette.inkPrimary
                                    )
                                    .frame(minWidth: 44, minHeight: 44)
                                    .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .disabled(chunkSize >= 64)
                            .accessibilityLabel("Increase chunk size")
                        }
                        .background {
                            Capsule()
                                .fill(palette.surfaceRaised)
                                .overlay {
                                    if colorSchemeContrast == .increased {
                                        Capsule()
                                            .strokeBorder(palette.borderStrong, lineWidth: 1.0)
                                    }
                                }
                                .frame(minHeight: 34)
                        }
                    }
                    .frame(minHeight: 44)
                    .padding(.leading, 16)
                    .padding(.trailing, 12)
                    .padding(.vertical, 4)
                }
            }

            SectionFooter("Splits outbound TLS ClientHello packets into smaller byte chunks (1-64 B) to evade deep packet inspection.")
        }
    }

    // MARK: - DNS & Privacy

    private var dnsSection: some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionHeader("DNS & Privacy")

            InsetGroupedCard(cornerRadius: 16) {
                VStack(spacing: 0) {
                    ForEach(Array(dnsPresets.enumerated()), id: \.element.id) { idx, preset in
                        if idx > 0 {
                            InsetDivider(leadingInset: 16)
                        }
                        let active = manager.settings.dnsAddr.caseInsensitiveCompare(preset.value) == .orderedSame
                        Button {
                            guard !active else { return }
                            VdpiHaptics.trigger(.selection)
                            focusedField = nil
                            dnsError = nil
                            dnsDraft = ""
                            withAnimation(reduceMotion ? nil : VdpiMotion.cardShift) {
                                manager.updateSettings { $0.dnsAddr = preset.value }
                            }
                        } label: {
                            HStack(spacing: 12) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(preset.label)
                                        .font(.body)
                                        .foregroundStyle(palette.inkPrimary)
                                    Text(preset.value)
                                        .font(.footnote)
                                        .monospacedDigit()
                                        .foregroundStyle(palette.inkSecondary)
                                }

                                Spacer(minLength: 8)

                                if active {
                                    Image(systemName: "checkmark")
                                        .font(.body.weight(.semibold))
                                        .foregroundStyle(palette.accent)
                                        .accessibilityHidden(true)
                                }
                            }
                            .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                            .padding(.horizontal, 16)
                            .padding(.vertical, 10)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(SettingsRowButtonStyle(highlightColor: palette.surfaceRaised))
                        .accessibilityAddTraits(active ? .isSelected : [])
                    }

                    InsetDivider(leadingInset: 16)

                    VStack(alignment: .leading, spacing: 6) {
                        HStack(spacing: 12) {
                            TextField("Custom IP or https:// DoH URL", text: $dnsDraft)
                                .font(.body)
                                .foregroundStyle(palette.inkPrimary)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled(true)
                                .keyboardType(.URL)
                                .submitLabel(.done)
                                .focused($focusedField, equals: .dns)
                                .frame(minHeight: 44)
                                .onSubmit { commitDns() }

                            if isCustomDnsActive {
                                Image(systemName: "checkmark")
                                    .font(.body.weight(.semibold))
                                    .foregroundStyle(palette.accent)
                                    .accessibilityLabel("Active custom DNS")
                            } else {
                                Button("Apply") {
                                    commitDns()
                                }
                                .font(.body.weight(.semibold))
                                .foregroundStyle(canApplyDns ? palette.accent : palette.inkMuted)
                                .fixedSize(horizontal: true, vertical: false)
                                .frame(minWidth: 44, minHeight: 44)
                                .contentShape(Rectangle())
                                .buttonStyle(.plain)
                                .disabled(!canApplyDns)
                            }
                        }

                        if let dnsError {
                            Text(dnsError)
                                .font(.footnote)
                                .foregroundStyle(palette.danger)
                                .fixedSize(horizontal: false, vertical: true)
                                .padding(.bottom, 6)
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 4)

                    InsetDivider(leadingInset: 16)

                    toggleRow(
                        title: "DNS over HTTPS",
                        isOn: Binding(
                            get: { manager.settings.enableDoh },
                            set: { val in
                                manager.updateSettings { $0.enableDoh = val }
                            }
                        )
                    )

                    InsetDivider(leadingInset: 16)

                    toggleRow(
                        title: "Block QUIC",
                        isOn: Binding(
                            get: { manager.settings.blockQuic },
                            set: { val in
                                manager.updateSettings { $0.blockQuic = val }
                            }
                        )
                    )

                    InsetDivider(leadingInset: 16)

                    toggleRow(
                        title: "IPv4 Only",
                        isOn: Binding(
                            get: { manager.settings.ipv4Only },
                            set: { val in
                                manager.updateSettings { $0.ipv4Only = val }
                            }
                        )
                    )
                }
            }

            SectionFooter("Encrypts resolver lookups with DoH and blocks UDP/443 QUIC so traffic falls back to TCP where TLS desync applies.")
        }
    }

    // MARK: - Tunnel

    private var tunnelSection: some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionHeader("Tunnel")

            InsetGroupedCard(cornerRadius: 16) {
                toggleRow(
                    title: "Connect On-Demand",
                    isOn: Binding(
                        get: { manager.settings.onDemandEnabled },
                        set: { val in
                            manager.updateSettings { $0.onDemandEnabled = val }
                        }
                    )
                )
            }

            SectionFooter("Automatically keeps the vdpi tunnel active when switching between Wi-Fi and cellular networks.")
        }
    }

    // MARK: - Bypass Domains

    private var bypassDomainsSection: some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionHeader("Bypass Domains")

            InsetGroupedCard(cornerRadius: 16) {
                VStack(spacing: 0) {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(spacing: 12) {
                            TextField("Add domain (e.g. example.com)", text: $bypassDraft)
                                .font(.body)
                                .foregroundStyle(palette.inkPrimary)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled(true)
                                .keyboardType(.URL)
                                .submitLabel(.done)
                                .focused($focusedField, equals: .bypass)
                                .frame(minHeight: 44)
                                .onSubmit { addBypassDomain() }

                            Button("Add") {
                                addBypassDomain()
                            }
                            .font(.body.weight(.semibold))
                            .foregroundStyle(canAddBypass ? palette.accent : palette.inkMuted)
                            .fixedSize(horizontal: true, vertical: false)
                            .frame(minWidth: 44, minHeight: 44)
                            .contentShape(Rectangle())
                            .buttonStyle(.plain)
                            .disabled(!canAddBypass)
                        }

                        if let bypassError {
                            Text(bypassError)
                                .font(.footnote)
                                .foregroundStyle(palette.danger)
                                .fixedSize(horizontal: false, vertical: true)
                                .padding(.bottom, 6)
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 4)

                    ForEach(manager.settings.bypassDomains, id: \.self) { domain in
                        InsetDivider(leadingInset: 16)

                        HStack(spacing: 8) {
                            Text(domain)
                                .font(.body)
                                .foregroundStyle(palette.inkPrimary)
                                .lineLimit(1)
                                .truncationMode(.middle)

                            Spacer(minLength: 8)

                            Button {
                                VdpiHaptics.trigger(.light)
                                withAnimation(reduceMotion ? nil : VdpiMotion.cardShift) {
                                    manager.updateSettings {
                                        $0.bypassDomains.removeAll { $0 == domain }
                                    }
                                }
                            } label: {
                                Image(systemName: "minus.circle.fill")
                                    .font(.title3)
                                    .foregroundStyle(palette.danger)
                                    .frame(width: 44, height: 44)
                                    .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel("Remove \(domain)")
                        }
                        .frame(minHeight: 44)
                        .padding(.leading, 16)
                        .padding(.trailing, 4)
                        .transition(.opacity)
                    }
                }
                .animation(reduceMotion ? nil : VdpiMotion.cardShift, value: manager.settings.bypassDomains)
            }

            SectionFooter("Matching domains and subdomains skip TLS desync. Local networks, banking, and government portals are bypassed automatically.")
        }
    }

    // MARK: - Appearance

    private var appearanceSection: some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionHeader("Appearance")

            InsetGroupedCard(cornerRadius: 16) {
                Picker(
                    "Appearance",
                    selection: Binding(
                        get: { manager.settings.theme },
                        set: { pref in
                            guard manager.settings.theme != pref else { return }
                            manager.updateSettings { $0.theme = pref }
                        }
                    )
                ) {
                    ForEach(ThemePreference.allCases) { pref in
                        Text(pref.label).tag(pref)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .padding(.horizontal, 12)
                .padding(.vertical, 10)
            }

            SectionFooter("System matches your device Light and Dark appearance automatically.")
        }
    }

    // MARK: - Backup & Restore

    private var backupSection: some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionHeader("Backup & Restore")

            InsetGroupedCard(cornerRadius: 16) {
                VStack(spacing: 0) {
                    Button {
                        VdpiHaptics.trigger(.light)
                        focusedField = nil
                        if let json = manager.exportSettingsJSON() {
                            exportDocument = VdpiSettingsDocument(jsonText: json)
                            showSettingsExporter = true
                        } else {
                            VdpiHaptics.trigger(.warning)
                            manager.showToast("Could not export settings")
                        }
                    } label: {
                        HStack(spacing: 12) {
                            Image(systemName: "square.and.arrow.up")
                                .font(.body)
                                .foregroundStyle(palette.accent)
                                .frame(width: 24)
                                .accessibilityHidden(true)

                            Text("Export Settings")
                                .font(.body)
                                .foregroundStyle(palette.inkPrimary)

                            Spacer(minLength: 8)
                        }
                        .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 6)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(SettingsRowButtonStyle(highlightColor: palette.surfaceRaised))

                    InsetDivider(leadingInset: 16)

                    Button {
                        VdpiHaptics.trigger(.light)
                        focusedField = nil
                        showSettingsImporter = true
                    } label: {
                        HStack(spacing: 12) {
                            Image(systemName: "square.and.arrow.down")
                                .font(.body)
                                .foregroundStyle(palette.accent)
                                .frame(width: 24)
                                .accessibilityHidden(true)

                            Text("Import Settings")
                                .font(.body)
                                .foregroundStyle(palette.inkPrimary)

                            Spacer(minLength: 8)
                        }
                        .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 6)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(SettingsRowButtonStyle(highlightColor: palette.surfaceRaised))
                }
            }

            SectionFooter("Save your desync, DNS, and bypass configuration as JSON or restore from a previous backup.")
        }
    }

    // MARK: - Updates

    private var updatesSection: some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionHeader("Updates")

            InsetGroupedCard(cornerRadius: 16) {
                if let update = manager.availableUpdate {
                    let latest = formattedVersion(update.latestVersion)
                    let destination = URL(string: update.releaseURL) ?? Self.githubRepositoryURL
                    Link(destination: destination) {
                        HStack(spacing: 10) {
                            Circle()
                                .fill(palette.accent)
                                .frame(width: 6, height: 6)
                                .accessibilityHidden(true)

                            VStack(alignment: .leading, spacing: 2) {
                                Text("Update Available · \(latest)")
                                    .font(.body)
                                    .foregroundStyle(palette.inkPrimary)

                                Text("Current \(formattedVersion(manager.appVersion)) · Open GitHub Release")
                                    .font(.footnote)
                                    .foregroundStyle(palette.inkSecondary)
                                    .lineLimit(1)
                                    .truncationMode(.tail)
                            }

                            Spacer(minLength: 8)

                            Image(systemName: "arrow.up.right")
                                .font(.subheadline.weight(.semibold))
                                .foregroundStyle(palette.accent)
                                .accessibilityHidden(true)
                        }
                        .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 10)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(SettingsRowButtonStyle(highlightColor: palette.surfaceRaised))
                    .accessibilityLabel("Update available, \(latest). Open GitHub release")
                } else {
                    Button {
                        VdpiHaptics.trigger(.light)
                        focusedField = nil
                        manager.checkForUpdates(manual: true)
                    } label: {
                        HStack(spacing: 12) {
                            Text("Check for Updates")
                                .font(.body)
                                .foregroundStyle(palette.inkPrimary)

                            Spacer(minLength: 8)

                            if manager.isCheckingUpdate {
                                ProgressView()
                                    .progressViewStyle(.circular)
                                    .controlSize(.small)
                                    .tint(palette.inkSecondary)
                                    .accessibilityLabel("Checking for updates")
                            } else {
                                let statusText: String = {
                                    if let msg = manager.updateStatusMessage, !msg.isEmpty {
                                        return msg
                                    }
                                    return formattedVersion(manager.appVersion)
                                }()
                                Text(statusText)
                                    .font(.subheadline)
                                    .monospacedDigit()
                                    .foregroundStyle(palette.inkSecondary)
                                    .lineLimit(1)
                                    .truncationMode(.tail)
                            }
                        }
                        .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 6)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(SettingsRowButtonStyle(highlightColor: palette.surfaceRaised))
                    .disabled(manager.isCheckingUpdate)
                }
            }
        }
    }

    // MARK: - Reset

    private var resetSection: some View {
        InsetGroupedCard(cornerRadius: 16) {
            Button(role: .destructive) {
                VdpiHaptics.trigger(.warning)
                focusedField = nil
                showResetConfirm = true
            } label: {
                Text("Reset to Defaults")
                    .font(.body)
                    .foregroundStyle(palette.danger)
                    .frame(maxWidth: .infinity, minHeight: 44)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 4)
                    .contentShape(Rectangle())
            }
            .buttonStyle(SettingsRowButtonStyle(highlightColor: palette.surfaceRaised))
        }
    }

    // MARK: - About

    private var aboutSection: some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionHeader("About")

            InsetGroupedCard(cornerRadius: 16) {
                Link(destination: Self.githubRepositoryURL) {
                    HStack(spacing: 12) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("GitHub Repository")
                                .font(.body)
                                .foregroundStyle(palette.inkPrimary)
                            Text("github.com/Vuln-Inc/vdpi")
                                .font(.footnote)
                                .foregroundStyle(palette.inkSecondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }

                        Spacer(minLength: 8)

                        Image(systemName: "arrow.up.right")
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(palette.inkMuted)
                            .accessibilityHidden(true)
                    }
                    .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                    .contentShape(Rectangle())
                }
                .buttonStyle(SettingsRowButtonStyle(highlightColor: palette.surfaceRaised))
                .accessibilityLabel("Open vdpi GitHub repository")
            }
        }
    }

    // MARK: - Version Footer

    private var versionFooter: some View {
        let ver = formattedVersion(manager.appVersion)
        return Text("vdpi \(ver) · github.com/Vuln-Inc/vdpi")
            .font(.footnote)
            .foregroundStyle(palette.inkMuted)
            .multilineTextAlignment(.center)
            .frame(maxWidth: .infinity, alignment: .center)
            .padding(.top, -4)
    }

    private func formattedVersion(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "v0.5.1" }
        return trimmed.lowercased().hasPrefix("v") ? trimmed : "v\(trimmed)"
    }

    // MARK: - Row Helpers

    private func toggleRow(title: String, isOn: Binding<Bool>) -> some View {
        Toggle(isOn: isOn) {
            Text(title)
                .font(.body)
                .foregroundStyle(palette.inkPrimary)
        }
        .tint(palette.signal)
        .frame(minHeight: 44)
        .padding(.horizontal, 16)
        .padding(.vertical, 6)
    }

    // MARK: - Actions

    private func commitDns() {
        let trimmed = dnsDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            focusedField = nil
            dnsError = nil
            dnsDraft = draftValue(for: manager.settings.dnsAddr)
            return
        }
        guard VdpiFormatters.isValidDnsInput(trimmed) else {
            VdpiHaptics.trigger(.warning)
            dnsError = "Enter an IPv4, IPv6, or https:// DoH URL"
            return
        }
        focusedField = nil
        dnsError = nil
        dnsDraft = draftValue(for: trimmed)
        if trimmed.caseInsensitiveCompare(manager.settings.dnsAddr) != .orderedSame {
            VdpiHaptics.trigger(.success)
            manager.updateSettings { $0.dnsAddr = trimmed }
            manager.showToast("Updated DNS resolver")
        }
    }

    private func addBypassDomain() {
        guard let normalized = VdpiFormatters.normalizeBypassDomain(bypassDraft) else {
            VdpiHaptics.trigger(.warning)
            bypassError = "Enter a valid domain such as example.com or *.example.com"
            return
        }
        if manager.settings.bypassDomains.contains(normalized) {
            VdpiHaptics.trigger(.warning)
            bypassError = "Already in bypass list"
            return
        }
        focusedField = nil
        bypassError = nil
        bypassDraft = ""
        VdpiHaptics.trigger(.success)
        withAnimation(reduceMotion ? nil : VdpiMotion.cardShift) {
            manager.updateSettings { s in
                if !s.bypassDomains.contains(normalized) {
                    s.bypassDomains.append(normalized)
                    s.bypassDomains.sort()
                }
            }
        }
    }

    private func importSettings(from url: URL) {
        let didAccess = url.startAccessingSecurityScopedResource()
        defer {
            if didAccess {
                url.stopAccessingSecurityScopedResource()
            }
        }
        do {
            let resourceValues = try url.resourceValues(forKeys: [.fileSizeKey])
            if let fileSize = resourceValues.fileSize, fileSize > 262_144 {
                VdpiHaptics.trigger(.warning)
                manager.showToast("Invalid settings file")
                return
            }
            let data = try Data(contentsOf: url)
            guard data.count <= 262_144, let rawJSON = String(data: data, encoding: .utf8) else {
                VdpiHaptics.trigger(.warning)
                manager.showToast("Invalid settings file")
                return
            }
            try manager.importSettingsJSON(rawJSON)
            dnsDraft = draftValue(for: manager.settings.dnsAddr)
            dnsError = nil
            bypassError = nil
            VdpiHaptics.trigger(.success)
        } catch {
            VdpiHaptics.trigger(.warning)
            manager.showToast("Invalid settings file")
        }
    }
}

// MARK: - Settings Export Document

private struct VdpiSettingsDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.json, .plainText] }

    var jsonText: String

    init(jsonText: String = "{}") {
        self.jsonText = jsonText
    }

    init(configuration: ReadConfiguration) throws {
        if let data = configuration.file.regularFileContents,
           let text = String(data: data, encoding: .utf8)
        {
            self.jsonText = text
        } else {
            self.jsonText = "{}"
        }
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: Data(jsonText.utf8))
    }
}

// MARK: - Row Button Style

private struct SettingsRowButtonStyle: ButtonStyle {
    let highlightColor: Color

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .background(configuration.isPressed ? highlightColor.opacity(0.65) : Color.clear)
    }
}
