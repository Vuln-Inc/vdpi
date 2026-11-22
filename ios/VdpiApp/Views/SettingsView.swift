import SwiftUI

struct SettingsView: View {
    var topInset: CGFloat = 0
    var bottomInset: CGFloat = 104

    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette

    private enum Field: Hashable {
        case dns
        case bypass
    }

    @State private var dnsDraft: String = ""
    @State private var dnsError: String? = nil
    @State private var bypassDraft: String = ""
    @State private var bypassError: String? = nil
    @State private var showResetConfirm = false
    @FocusState private var focusedField: Field?
    @Namespace private var themeNamespace

    private let dnsPresets: [(label: String, value: String)] = [
        ("Cloudflare", "1.1.1.1"),
        ("Google", "8.8.8.8"),
        ("Quad9", "9.9.9.9"),
        ("AdGuard", "94.140.14.140"),
    ]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                headerBar

                desyncSection
                dnsSection
                tunnelBehaviorSection
                bypassDomainsSection
                appearanceSection
                resetButton
            }
            .animation(VdpiMotion.floatingHud, value: topInset)
            .animation(VdpiMotion.floatingHud, value: focusedField != nil)
            .padding(.horizontal, 16)
            .padding(.top, 12 + topInset)
            .padding(.bottom, bottomInset)
        }
        .scrollIndicators(.hidden)
        .scrollDismissesKeyboard(.interactively)
        .onAppear {
            dnsDraft = manager.settings.dnsAddr
        }
        .vdpiOnChange(of: manager.settings.dnsAddr) { newDns in
            if focusedField != .dns && dnsDraft != newDns {
                dnsDraft = newDns
                dnsError = nil
            }
        }
        .confirmationDialog(
            "Reset all tunnel settings to defaults?",
            isPresented: $showResetConfirm,
            titleVisibility: .visible
        ) {
            Button("Reset Defaults", role: .destructive) {
                VdpiHaptics.trigger(.warning)
                manager.resetSettings()
                dnsDraft = manager.settings.dnsAddr
                dnsError = nil
                bypassError = nil
            }
            Button("Cancel", role: .cancel) {}
        }
    }

    // MARK: - Header

    private var headerBar: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Settings")
                    .font(.system(size: 28, weight: .bold))
                    .tracking(-0.7)
                    .foregroundStyle(palette.inkPrimary)

                Text("Desync engine, DNS ring & routing")
                    .font(.system(size: 13))
                    .foregroundStyle(palette.inkSecondary)
            }

            Spacer()

            if focusedField != nil {
                GlassCircleButton(
                    systemImage: "keyboard.chevron.compact.down",
                    accessibilityLabel: "Dismiss keyboard"
                ) {
                    focusedField = nil
                }
                .transition(.scale(scale: 0.85).combined(with: .opacity))
            }
        }
    }

    // MARK: - TLS Desynchronization

    private var desyncSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionOverline(title: "TLS Desynchronization")

            GlassPanel(cornerRadius: 22) {
                VStack(spacing: 0) {
                    ForEach(Array(DesyncMode.allCases.enumerated()), id: \.element.id) { idx, mode in
                        if idx > 0 { HairlineRule() }
                        let selected = manager.settings.desyncMode == mode
                        Button {
                            guard !selected else { return }
                            VdpiHaptics.trigger(.selection)
                            withAnimation(VdpiMotion.cardShift) {
                                manager.updateSettings { $0.desyncMode = mode }
                            }
                        } label: {
                            HStack(spacing: 12) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(mode.label)
                                        .font(.system(size: 14, weight: .semibold))
                                        .foregroundStyle(palette.inkPrimary)
                                    Text(mode.subtitle)
                                        .font(.system(size: 12))
                                        .foregroundStyle(palette.inkSecondary)
                                }

                                Spacer()

                                ZStack {
                                    Circle()
                                        .strokeBorder(
                                            selected ? palette.signal : palette.borderStrong,
                                            lineWidth: 1.5
                                        )
                                        .frame(width: 22, height: 22)

                                    if selected {
                                        Image(systemName: "checkmark.circle.fill")
                                            .font(.system(size: 22))
                                            .foregroundStyle(palette.signal)
                                            .transition(.scale(scale: 0.5).combined(with: .opacity))
                                    }
                                }
                                .animation(VdpiMotion.tabLens, value: selected)
                            }
                            .frame(minHeight: 50)
                            .padding(.horizontal, 16)
                            .padding(.vertical, 8)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityAddTraits(selected ? .isSelected : [])
                    }

                    HairlineRule()

                    HStack(spacing: 12) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Chunk Size")
                                .font(.system(size: 14, weight: .semibold))
                                .foregroundStyle(palette.inkPrimary)
                            Text("TLS ClientHello split size in bytes (1–64)")
                                .font(.system(size: 12))
                                .foregroundStyle(palette.inkSecondary)
                        }

                        Spacer()

                        HStack(spacing: 2) {
                            Button {
                                VdpiHaptics.trigger(.light)
                                withAnimation(VdpiMotion.cardShift) {
                                    manager.updateSettings { $0.chunkSize = max(1, $0.chunkSize - 1) }
                                }
                            } label: {
                                Image(systemName: "minus")
                                    .font(.system(size: 13, weight: .semibold))
                                    .frame(width: 38, height: 38)
                                    .foregroundStyle(
                                        manager.settings.chunkSize <= 1 ? palette.inkMuted : palette.inkPrimary
                                    )
                                    .contentShape(Circle())
                            }
                            .buttonStyle(VdpiPressButtonStyle(haptic: nil))
                            .disabled(manager.settings.chunkSize <= 1)
                            .accessibilityLabel("Decrease chunk size")

                            Text("\(manager.settings.chunkSize) B")
                                .font(.system(size: 13, weight: .semibold, design: .monospaced))
                                .monospacedDigit()
                                .foregroundStyle(palette.inkPrimary)
                                .contentTransition(.numericText())
                                .frame(minWidth: 44)
                                .multilineTextAlignment(.center)

                            Button {
                                VdpiHaptics.trigger(.light)
                                withAnimation(VdpiMotion.cardShift) {
                                    manager.updateSettings { $0.chunkSize = min(64, $0.chunkSize + 1) }
                                }
                            } label: {
                                Image(systemName: "plus")
                                    .font(.system(size: 13, weight: .semibold))
                                    .frame(width: 38, height: 38)
                                    .foregroundStyle(
                                        manager.settings.chunkSize >= 64 ? palette.inkMuted : palette.inkPrimary
                                    )
                                    .contentShape(Circle())
                            }
                            .buttonStyle(VdpiPressButtonStyle(haptic: nil))
                            .disabled(manager.settings.chunkSize >= 64)
                            .accessibilityLabel("Increase chunk size")
                        }
                        .padding(3)
                        .vdpiGlass(in: Capsule(), tier: .subtle)
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
                }
            }
        }
    }

    // MARK: - DNS & Privacy

    private var dnsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionOverline(title: "DNS & Privacy")

            GlassPanel(cornerRadius: 22) {
                VStack(alignment: .leading, spacing: 0) {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Upstream Resolver")
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(palette.inkPrimary)

                        HStack(spacing: 8) {
                            TextField("1.1.1.1 or https://dns.google/dns-query", text: $dnsDraft)
                                .font(.system(size: 13.5, design: .monospaced))
                                .foregroundStyle(palette.inkPrimary)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled(true)
                                .keyboardType(.URL)
                                .submitLabel(.done)
                                .focused($focusedField, equals: .dns)
                                .padding(.horizontal, 14)
                                .frame(minHeight: 44)
                                .vdpiGlass(
                                    in: RoundedRectangle(cornerRadius: 14, style: .continuous),
                                    tier: .subtle,
                                    tint: dnsError != nil ? palette.dangerTint : nil,
                                    borderAccent: dnsError != nil
                                        ? palette.danger
                                        : (focusedField == .dns ? palette.borderStrong : nil)
                                )
                                .onSubmit { commitDns() }

                            Button("Save") {
                                commitDns()
                            }
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(palette.primaryButtonInk)
                            .padding(.horizontal, 16)
                            .frame(minHeight: 44)
                            .background(palette.primaryButtonBg)
                            .clipShape(Capsule())
                            .buttonStyle(VdpiPressButtonStyle(haptic: nil))
                        }

                        if let dnsError {
                            Text(dnsError)
                                .font(.system(size: 12))
                                .foregroundStyle(palette.danger)
                        }

                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 8) {
                                ForEach(dnsPresets, id: \.value) { preset in
                                    let active = manager.settings.dnsAddr == preset.value
                                    Button {
                                        VdpiHaptics.trigger(.selection)
                                        focusedField = nil
                                        dnsError = nil
                                        dnsDraft = preset.value
                                        withAnimation(VdpiMotion.cardShift) {
                                            manager.updateSettings { $0.dnsAddr = preset.value }
                                        }
                                    } label: {
                                        HStack(spacing: 6) {
                                            if active {
                                                Circle()
                                                    .fill(palette.signal)
                                                    .frame(width: 6, height: 6)
                                            }
                                            Text("\(preset.label) · \(preset.value)")
                                                .font(.system(size: 12, weight: .medium, design: .monospaced))
                                        }
                                        .foregroundStyle(active ? palette.inkPrimary : palette.inkSecondary)
                                        .padding(.horizontal, 13)
                                        .frame(minHeight: 38)
                                        .vdpiGlass(
                                            in: Capsule(),
                                            tier: active ? .regular : .subtle,
                                            tint: active ? palette.signalTint : nil,
                                            borderAccent: active ? palette.signal : nil,
                                            interactive: true
                                        )
                                    }
                                    .buttonStyle(VdpiPressButtonStyle(haptic: nil))
                                    .accessibilityAddTraits(active ? .isSelected : [])
                                }
                            }
                            .padding(.vertical, 2)
                        }
                    }
                    .padding(16)

                    HairlineRule()

                    toggleRow(
                        title: "DNS-over-HTTPS (RFC 8484)",
                        subtitle: "Sticky multi-provider DoH ring with sinkhole filtering",
                        isOn: Binding(
                            get: { manager.settings.enableDoh },
                            set: { val in
                                VdpiHaptics.trigger(.light)
                                manager.updateSettings { $0.enableDoh = val }
                            }
                        )
                    )

                    HairlineRule()

                    toggleRow(
                        title: "Block QUIC (UDP/443)",
                        subtitle: "Drops QUIC Initial packets so apps cleanly use TCP TLS",
                        isOn: Binding(
                            get: { manager.settings.blockQuic },
                            set: { val in
                                VdpiHaptics.trigger(.light)
                                manager.updateSettings { $0.blockQuic = val }
                            }
                        )
                    )

                    HairlineRule()

                    toggleRow(
                        title: "IPv4 Only",
                        subtitle: "Disable IPv6 tunnel routing and AAAA queries",
                        isOn: Binding(
                            get: { manager.settings.ipv4Only },
                            set: { val in
                                VdpiHaptics.trigger(.light)
                                manager.updateSettings { $0.ipv4Only = val }
                            }
                        )
                    )
                }
            }
        }
    }

    // MARK: - Tunnel Behavior

    private var tunnelBehaviorSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionOverline(title: "Tunnel Behavior")

            GlassPanel(cornerRadius: 22) {
                VStack(spacing: 0) {
                    toggleRow(
                        title: "Connect On-Demand",
                        subtitle: "Automatically keep vdpi active across Wi-Fi and Cellular",
                        isOn: Binding(
                            get: { manager.settings.onDemandEnabled },
                            set: { val in
                                VdpiHaptics.trigger(.light)
                                manager.updateSettings { $0.onDemandEnabled = val }
                            }
                        )
                    )
                }
            }
        }
    }

    // MARK: - Domain Bypass

    private var bypassDomainsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionOverline(title: "Domain Bypass")

            GlassPanel(cornerRadius: 22) {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Domains here skip TLS fragmentation (LAN, banking, and government portals are already bypassed automatically). Consumer iOS restricts per-app VPN routing to MDM.")
                        .font(.system(size: 12))
                        .foregroundStyle(palette.inkSecondary)
                        .fixedSize(horizontal: false, vertical: true)

                    HStack(spacing: 8) {
                        TextField("e.g. *.example.com", text: $bypassDraft)
                            .font(.system(size: 13.5, design: .monospaced))
                            .foregroundStyle(palette.inkPrimary)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled(true)
                            .submitLabel(.done)
                            .focused($focusedField, equals: .bypass)
                            .padding(.horizontal, 14)
                            .frame(minHeight: 44)
                            .vdpiGlass(
                                in: RoundedRectangle(cornerRadius: 14, style: .continuous),
                                tier: .subtle,
                                tint: bypassError != nil ? palette.dangerTint : nil,
                                borderAccent: bypassError != nil
                                    ? palette.danger
                                    : (focusedField == .bypass ? palette.borderStrong : nil)
                            )
                            .onSubmit { addBypassDomain() }

                        Button("Add") {
                            addBypassDomain()
                        }
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(palette.primaryButtonInk)
                        .padding(.horizontal, 16)
                        .frame(minHeight: 44)
                        .background(palette.primaryButtonBg)
                        .clipShape(Capsule())
                        .buttonStyle(VdpiPressButtonStyle(haptic: nil))
                    }

                    if let bypassError {
                        Text(bypassError)
                            .font(.system(size: 12))
                            .foregroundStyle(palette.danger)
                    }

                    if !manager.settings.bypassDomains.isEmpty {
                        VStack(spacing: 8) {
                            ForEach(manager.settings.bypassDomains, id: \.self) { domain in
                                HStack(spacing: 10) {
                                    Text(domain)
                                        .font(.system(size: 13, weight: .medium, design: .monospaced))
                                        .foregroundStyle(palette.inkPrimary)
                                        .lineLimit(1)
                                        .truncationMode(.middle)

                                    Spacer()

                                    Button {
                                        VdpiHaptics.trigger(.light)
                                        withAnimation(VdpiMotion.cardShift) {
                                            manager.updateSettings {
                                                $0.bypassDomains.removeAll { $0 == domain }
                                            }
                                        }
                                    } label: {
                                        Image(systemName: "xmark")
                                            .font(.system(size: 11, weight: .bold))
                                            .foregroundStyle(palette.inkMuted)
                                            .frame(width: 32, height: 32)
                                            .contentShape(Circle())
                                    }
                                    .buttonStyle(VdpiPressButtonStyle(haptic: nil))
                                    .accessibilityLabel("Remove \(domain)")
                                }
                                .padding(.leading, 14)
                                .padding(.trailing, 6)
                                .frame(minHeight: 42)
                                .vdpiGlass(in: Capsule(), tier: .subtle)
                                .transition(.opacity.combined(with: .scale(scale: 0.94)))
                            }
                        }
                        .animation(VdpiMotion.cardShift, value: manager.settings.bypassDomains)
                    }
                }
                .padding(16)
            }
        }
    }

    // MARK: - Appearance

    private var appearanceSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionOverline(title: "Appearance")

            GlassPanel(cornerRadius: 22) {
                HStack(spacing: 4) {
                    ForEach(ThemePreference.allCases) { pref in
                        let selected = manager.settings.theme == pref
                        Button {
                            guard !selected else { return }
                            VdpiHaptics.trigger(.selection)
                            withAnimation(VdpiMotion.tabLens) {
                                manager.updateSettings { $0.theme = pref }
                            }
                        } label: {
                            Text(pref.label)
                                .font(.system(size: 13.5, weight: selected ? .semibold : .medium))
                                .frame(maxWidth: .infinity)
                                .frame(minHeight: 44)
                                .foregroundStyle(selected ? palette.inkPrimary : palette.inkMuted)
                                .background {
                                    if selected {
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
                                            .matchedGeometryEffect(id: "vdpi.theme.lens", in: themeNamespace)
                                    }
                                }
                                .contentShape(Capsule())
                        }
                        .buttonStyle(.plain)
                        .accessibilityAddTraits(selected ? .isSelected : [])
                    }
                }
                .padding(6)
            }
        }
    }

    // MARK: - Reset to Defaults

    private var resetButton: some View {
        Button {
            VdpiHaptics.trigger(.warning)
            showResetConfirm = true
        } label: {
            HStack(spacing: 8) {
                Image(systemName: "arrow.counterclockwise")
                    .font(.system(size: 13.5, weight: .semibold))
                Text("Reset to Defaults")
                    .font(.system(size: 14, weight: .semibold))
            }
            .foregroundStyle(palette.danger)
            .frame(maxWidth: .infinity)
            .frame(minHeight: 50)
            .vdpiGlass(
                in: Capsule(),
                tier: .regular,
                tint: palette.dangerTint,
                borderAccent: palette.danger,
                interactive: true
            )
        }
        .buttonStyle(VdpiPressButtonStyle(haptic: nil))
    }

    // MARK: - Helpers

    private func toggleRow(title: String, subtitle: String, isOn: Binding<Bool>) -> some View {
        Toggle(isOn: isOn) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(palette.inkPrimary)
                Text(subtitle)
                    .font(.system(size: 12))
                    .foregroundStyle(palette.inkSecondary)
            }
        }
        .tint(palette.signal)
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private func commitDns() {
        focusedField = nil
        let trimmed = dnsDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            dnsError = nil
            dnsDraft = "1.1.1.1"
            VdpiHaptics.trigger(.light)
            manager.updateSettings { $0.dnsAddr = "1.1.1.1" }
            return
        }
        guard VdpiFormatters.isValidDnsInput(trimmed) else {
            VdpiHaptics.trigger(.warning)
            dnsError = "Enter an IPv4, IPv6, or https:// DoH URL"
            return
        }
        dnsError = nil
        dnsDraft = trimmed
        VdpiHaptics.trigger(.success)
        manager.updateSettings { $0.dnsAddr = trimmed }
        manager.showToast("Updated DNS resolver")
    }

    private func addBypassDomain() {
        focusedField = nil
        guard let normalized = VdpiFormatters.normalizeBypassDomain(bypassDraft) else {
            VdpiHaptics.trigger(.warning)
            bypassError = "Enter a valid domain such as example.com or *.example.com"
            return
        }
        bypassError = nil
        bypassDraft = ""
        VdpiHaptics.trigger(.success)
        withAnimation(VdpiMotion.cardShift) {
            manager.updateSettings { s in
                if !s.bypassDomains.contains(normalized) {
                    s.bypassDomains.append(normalized)
                    s.bypassDomains.sort()
                }
            }
        }
    }
}
