import SwiftUI
import UniformTypeIdentifiers

struct SettingsView: View {
    var topInset: CGFloat = 0
    var bottomInset: CGFloat = 104

    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.appLanguage) private var appLanguage
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

    private enum DnsValidationError: Equatable {
        case invalidEndpoint
    }

    private enum BypassValidationError: Equatable {
        case invalidDomain
        case duplicate
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
    @State private var dnsError: DnsValidationError?
    @State private var bypassDraft: String = ""
    @State private var bypassError: BypassValidationError?
    @State private var showResetConfirm = false
    @State private var showSettingsExporter = false
    @State private var exportDocument = VdpiSettingsDocument()
    @State private var showSettingsImporter = false
    @FocusState private var focusedField: Field?

    // MARK: - Derived State

    private var l10n: L10n.Catalog {
        L10n.catalog(for: appLanguage)
    }

    private func isPresetDns(_ addr: String) -> Bool {
        dnsPresets.contains { $0.value.caseInsensitiveCompare(addr) == .orderedSame }
    }

    private func draftValue(for dnsAddr: String) -> String {
        isPresetDns(dnsAddr) ? "" : dnsAddr
    }

    private func isSameDnsEndpoint(_ lhs: String, _ rhs: String) -> Bool {
        let a = lhs.trimmingCharacters(in: .whitespacesAndNewlines)
        let b = rhs.trimmingCharacters(in: .whitespacesAndNewlines)
        if a.lowercased().hasPrefix("https://") || b.lowercased().hasPrefix("https://") {
            return a == b
        }
        return a.caseInsensitiveCompare(b) == .orderedSame
    }

    private var isHttpsDohActive: Bool {
        manager.settings.dnsAddr
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .hasPrefix("https://")
    }

    private var isCustomDnsActive: Bool {
        let current = manager.settings.dnsAddr
        guard !isPresetDns(current) else { return false }
        let trimmed = dnsDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        let needsDohEnable = trimmed.lowercased().hasPrefix("https://") && !manager.settings.enableDoh
        return !needsDohEnable && isSameDnsEndpoint(trimmed, current)
    }

    private var canApplyDns: Bool {
        let trimmed = dnsDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
        let needsDohEnable = trimmed.lowercased().hasPrefix("https://") && !manager.settings.enableDoh
        return needsDohEnable || !isSameDnsEndpoint(trimmed, manager.settings.dnsAddr)
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
                languageSection
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
            l10n.resetConfirmTitle,
            isPresented: $showResetConfirm,
            titleVisibility: .visible
        ) {
            Button(l10n.resetToDefaults, role: .destructive) {
                VdpiHaptics.trigger(.warning)
                focusedField = nil
                manager.resetSettings()
                dnsDraft = draftValue(for: manager.settings.dnsAddr)
                dnsError = nil
                bypassError = nil
            }
            Button(l10n.cancel, role: .cancel) {}
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
                manager.showToast(l10n.toastExportedSettings)
            case .failure(let error):
                let nsError = error as NSError
                if nsError.domain == NSCocoaErrorDomain && nsError.code == NSUserCancelledError {
                    return
                }
                VdpiHaptics.trigger(.warning)
                manager.showToast(l10n.toastExportFailed)
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
                manager.showToast(l10n.toastImportFailed)
            }
        }
    }

    // MARK: - Header

    private var headerBar: some View {
        HStack(alignment: .center, spacing: 12) {
            Text(l10n.tabSettings)
                .font(.largeTitle.bold())
                .foregroundStyle(palette.inkPrimary)
                .accessibilityAddTraits(.isHeader)

            Spacer(minLength: 8)

            if focusedField != nil {
                GlassCircleButton(
                    systemImage: "keyboard.chevron.compact.down",
                    accessibilityLabel: l10n.accessibilityDismissKeyboard
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
            SectionHeader(l10n.sectionDesyncEngine)

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
                                    Text(mode.label(in: appLanguage))
                                        .font(.body)
                                        .foregroundStyle(palette.inkPrimary)
                                    Text(mode.subtitle(in: appLanguage))
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
                        Text(l10n.chunkSizeLabel)
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
                            .accessibilityLabel(l10n.accessibilityDecreaseChunk)

                            Text("\(chunkSize) B")
                                .font(.subheadline.weight(.semibold))
                                .monospacedDigit()
                                .foregroundStyle(palette.inkPrimary)
                                .contentTransition(.numericText())
                                .frame(minWidth: 44)
                                .multilineTextAlignment(.center)
                                .accessibilityLabel(l10n.accessibilityChunkSizeBytes(chunkSize))

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
                            .accessibilityLabel(l10n.accessibilityIncreaseChunk)
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

            SectionFooter(l10n.desyncFooter)
        }
    }

    // MARK: - DNS & Privacy

    private var dnsSection: some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionHeader(l10n.sectionDnsPrivacy)

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
                            TextField(l10n.customDnsPlaceholder, text: $dnsDraft)
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
                                    .accessibilityLabel(l10n.accessibilityActiveCustomDns)
                            } else {
                                Button(l10n.apply) {
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

                        if dnsError != nil {
                            Text(l10n.dnsValidationError)
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
                        title: l10n.toggleDoh,
                        subtitle: isHttpsDohActive ? l10n.toggleDohForcedSubtitle : nil,
                        isOn: Binding(
                            get: { isHttpsDohActive || manager.settings.enableDoh },
                            set: { val in
                                guard !isHttpsDohActive else { return }
                                manager.updateSettings { $0.enableDoh = val }
                            }
                        ),
                        disabled: isHttpsDohActive
                    )

                    InsetDivider(leadingInset: 16)

                    toggleRow(
                        title: l10n.toggleBlockQuic,
                        isOn: Binding(
                            get: { manager.settings.blockQuic },
                            set: { val in
                                manager.updateSettings { $0.blockQuic = val }
                            }
                        )
                    )

                    InsetDivider(leadingInset: 16)

                    toggleRow(
                        title: l10n.toggleIpv4Only,
                        isOn: Binding(
                            get: { manager.settings.ipv4Only },
                            set: { val in
                                manager.updateSettings { $0.ipv4Only = val }
                            }
                        )
                    )
                }
            }

            SectionFooter(l10n.dnsFooter)
        }
    }

    // MARK: - Tunnel

    private var tunnelSection: some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionHeader(l10n.sectionTunnel)

            InsetGroupedCard(cornerRadius: 16) {
                toggleRow(
                    title: l10n.toggleConnectOnDemand,
                    isOn: Binding(
                        get: { manager.settings.onDemandEnabled },
                        set: { val in
                            manager.updateSettings { $0.onDemandEnabled = val }
                        }
                    )
                )
            }

            SectionFooter(l10n.tunnelFooter)
        }
    }

    // MARK: - Bypass Domains

    private var bypassDomainsSection: some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionHeader(l10n.sectionBypassDomains)

            InsetGroupedCard(cornerRadius: 16) {
                VStack(spacing: 0) {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(spacing: 12) {
                            TextField(l10n.bypassPlaceholder, text: $bypassDraft)
                                .font(.body)
                                .foregroundStyle(palette.inkPrimary)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled(true)
                                .keyboardType(.URL)
                                .submitLabel(.done)
                                .focused($focusedField, equals: .bypass)
                                .frame(minHeight: 44)
                                .onSubmit { addBypassDomain() }

                            Button(l10n.add) {
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
                            Text(
                                bypassError == .duplicate
                                    ? l10n.bypassDuplicateError
                                    : l10n.bypassInvalidError
                            )
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
                            .accessibilityLabel(l10n.accessibilityRemoveDomain(domain))
                        }
                        .frame(minHeight: 44)
                        .padding(.leading, 16)
                        .padding(.trailing, 4)
                        .transition(.opacity)
                    }
                }
                .animation(reduceMotion ? nil : VdpiMotion.cardShift, value: manager.settings.bypassDomains)
            }

            SectionFooter(l10n.bypassFooter)
        }
    }

    // MARK: - Appearance

    private var appearanceSection: some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionHeader(l10n.sectionAppearance)

            InsetGroupedCard(cornerRadius: 16) {
                Picker(
                    l10n.sectionAppearance,
                    selection: Binding(
                        get: { manager.settings.theme },
                        set: { pref in
                            guard manager.settings.theme != pref else { return }
                            manager.updateSettings { $0.theme = pref }
                        }
                    )
                ) {
                    ForEach(ThemePreference.allCases) { pref in
                        Text(pref.label(in: appLanguage)).tag(pref)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .padding(.horizontal, 12)
                .padding(.vertical, 10)
            }

            SectionFooter(l10n.appearanceFooter)
        }
    }

    // MARK: - Language

    private var languageSection: some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionHeader(l10n.sectionLanguage)

            InsetGroupedCard(cornerRadius: 16) {
                Picker(
                    l10n.sectionLanguage,
                    selection: Binding(
                        get: { manager.settings.language },
                        set: { lang in
                            guard manager.settings.language != lang else { return }
                            manager.updateSettings { $0.language = lang }
                        }
                    )
                ) {
                    ForEach(AppLanguage.allCases) { lang in
                        Text(lang.label(in: appLanguage)).tag(lang)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .padding(.horizontal, 12)
                .padding(.vertical, 10)
            }

            SectionFooter(l10n.languageFooter)
        }
    }

    // MARK: - Backup & Restore

    private var backupSection: some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionHeader(l10n.sectionBackupRestore)

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
                            manager.showToast(l10n.toastCouldNotExport)
                        }
                    } label: {
                        HStack(spacing: 12) {
                            Image(systemName: "square.and.arrow.up")
                                .font(.body)
                                .foregroundStyle(palette.accent)
                                .frame(width: 24)
                                .accessibilityHidden(true)

                            Text(l10n.exportSettings)
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

                            Text(l10n.importSettings)
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

            SectionFooter(l10n.backupFooter)
        }
    }

    // MARK: - Updates

    private var updatesSection: some View {
        VStack(alignment: .leading, spacing: 7) {
            SectionHeader(l10n.sectionUpdates)

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
                                Text(l10n.updateAvailableRowTitle(version: latest))
                                    .font(.body)
                                    .foregroundStyle(palette.inkPrimary)

                                Text(l10n.updateAvailableRowSubtitle(currentVersion: formattedVersion(manager.appVersion)))
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
                    .accessibilityLabel(l10n.accessibilityUpdateRow(version: latest))
                } else {
                    Button {
                        VdpiHaptics.trigger(.light)
                        focusedField = nil
                        manager.checkForUpdates(manual: true)
                    } label: {
                        HStack(spacing: 12) {
                            Text(l10n.checkForUpdates)
                                .font(.body)
                                .foregroundStyle(palette.inkPrimary)

                            Spacer(minLength: 8)

                            if manager.isCheckingUpdate {
                                ProgressView()
                                    .progressViewStyle(.circular)
                                    .controlSize(.small)
                                    .tint(palette.inkSecondary)
                                    .accessibilityLabel(l10n.accessibilityCheckingUpdates)
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
                Text(l10n.resetToDefaults)
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
            SectionHeader(l10n.sectionAbout)

            InsetGroupedCard(cornerRadius: 16) {
                Link(destination: Self.githubRepositoryURL) {
                    HStack(spacing: 12) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(l10n.githubRepository)
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
                .accessibilityLabel(l10n.accessibilityOpenGithub)
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
        guard !trimmed.isEmpty else { return "v0.6.1" }
        return trimmed.lowercased().hasPrefix("v") ? trimmed : "v\(trimmed)"
    }

    // MARK: - Row Helpers

    private func toggleRow(
        title: String,
        subtitle: String? = nil,
        isOn: Binding<Bool>,
        disabled: Bool = false
    ) -> some View {
        Toggle(isOn: isOn) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.body)
                    .foregroundStyle(disabled ? palette.inkSecondary : palette.inkPrimary)
                if let subtitle {
                    Text(subtitle)
                        .font(.footnote)
                        .foregroundStyle(palette.inkSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .tint(palette.signal)
        .disabled(disabled)
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
            dnsError = .invalidEndpoint
            return
        }
        focusedField = nil
        dnsError = nil
        dnsDraft = draftValue(for: trimmed)
        let isHttpsDoh = trimmed.lowercased().hasPrefix("https://")
        let dnsChanged = !isSameDnsEndpoint(trimmed, manager.settings.dnsAddr)
        let shouldEnableDoh = isHttpsDoh && !manager.settings.enableDoh
        if dnsChanged || shouldEnableDoh {
            VdpiHaptics.trigger(.success)
            manager.updateSettings { settings in
                settings.dnsAddr = trimmed
                if isHttpsDoh {
                    settings.enableDoh = true
                }
            }
            manager.showToast(l10n.toastUpdatedDns)
        }
    }

    private func addBypassDomain() {
        guard let normalized = VdpiFormatters.normalizeBypassDomain(bypassDraft) else {
            VdpiHaptics.trigger(.warning)
            bypassError = .invalidDomain
            return
        }
        if manager.settings.bypassDomains.contains(normalized) {
            VdpiHaptics.trigger(.warning)
            bypassError = .duplicate
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
                manager.showToast(l10n.toastSettingsFileTooLarge)
                return
            }
            let data = try Data(contentsOf: url)
            guard data.count <= 262_144, let rawJSON = String(data: data, encoding: .utf8) else {
                VdpiHaptics.trigger(.warning)
                manager.showToast(
                    data.count > 262_144
                        ? l10n.toastSettingsFileTooLarge
                        : SettingsImportError.invalidJSON.localizedMessage(in: appLanguage)
                )
                return
            }
            try manager.importSettingsJSON(rawJSON)
            dnsDraft = draftValue(for: manager.settings.dnsAddr)
            dnsError = nil
            bypassError = nil
            VdpiHaptics.trigger(.success)
        } catch let importError as SettingsImportError {
            VdpiHaptics.trigger(.warning)
            manager.showToast(importError.localizedMessage(in: appLanguage))
        } catch {
            VdpiHaptics.trigger(.warning)
            let message = error.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
            manager.showToast(message.isEmpty ? l10n.toastInvalidSettingsFile : message)
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
