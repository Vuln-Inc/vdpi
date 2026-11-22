import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette

    @State private var dnsDraft: String = ""
    @State private var bypassDraft: String = ""
    @State private var bypassError: String? = nil
    @State private var showResetConfirm = false

    private let dnsPresets = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "94.140.14.140"]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    Text("Settings")
                        .font(.system(size: 22, weight: .semibold))
                        .tracking(-0.5)
                        .foregroundStyle(palette.inkPrimary)
                    Spacer()
                }

                desyncSection
                dnsSection
                tunnelBehaviorSection
                bypassDomainsSection
                appearanceSection

                Button {
                    showResetConfirm = true
                } label: {
                    Text("Reset to Defaults")
                        .font(.system(size: 14, weight: .medium))
                        .foregroundStyle(palette.danger)
                        .frame(maxWidth: .infinity)
                        .frame(minHeight: 46)
                        .background(palette.surface)
                        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                        .overlay(
                            RoundedRectangle(cornerRadius: 12, style: .continuous)
                                .strokeBorder(palette.danger.opacity(0.35), lineWidth: 1)
                        )
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 16)
            .padding(.top, 16)
            .padding(.bottom, 28)
        }
        .scrollIndicators(.hidden)
        .scrollDismissesKeyboard(.interactively)
        .onAppear {
            dnsDraft = manager.settings.dnsAddr
        }
        .confirmationDialog(
            "Reset all tunnel settings to defaults?",
            isPresented: $showResetConfirm,
            titleVisibility: .visible
        ) {
            Button("Reset Defaults", role: .destructive) {
                manager.resetSettings()
                dnsDraft = manager.settings.dnsAddr
            }
            Button("Cancel", role: .cancel) {}
        }
    }

    private var desyncSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionOverline(title: "TLS Desynchronization")

            HairlinePanel {
                VStack(spacing: 0) {
                    ForEach(Array(DesyncMode.allCases.enumerated()), id: \.element.id) { idx, mode in
                        if idx > 0 { HairlineRule() }
                        let selected = manager.settings.desyncMode == mode
                        Button {
                            manager.updateSettings { $0.desyncMode = mode }
                        } label: {
                            HStack(spacing: 12) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(mode.label)
                                        .font(.system(size: 14, weight: .medium))
                                        .foregroundStyle(palette.inkPrimary)
                                    Text(mode.subtitle)
                                        .font(.system(size: 12))
                                        .foregroundStyle(palette.inkSecondary)
                                }
                                Spacer()
                                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                                    .font(.system(size: 18))
                                    .foregroundStyle(selected ? palette.inkPrimary : palette.inkMuted)
                            }
                            .frame(minHeight: 48)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 8)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }

                    HairlineRule()

                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Chunk Size")
                                .font(.system(size: 14, weight: .medium))
                                .foregroundStyle(palette.inkPrimary)
                            Text("TLS ClientHello split size in bytes (1–64)")
                                .font(.system(size: 12))
                                .foregroundStyle(palette.inkSecondary)
                        }
                        Spacer()
                        Stepper(
                            value: Binding(
                                get: { manager.settings.chunkSize },
                                set: { val in manager.updateSettings { $0.chunkSize = max(1, min(64, val)) } }
                            ),
                            in: 1...64
                        ) {
                            Text("\(manager.settings.chunkSize) B")
                                .font(.system(size: 13, weight: .semibold, design: .monospaced))
                                .monospacedDigit()
                                .foregroundStyle(palette.inkPrimary)
                        }
                        .fixedSize()
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                }
            }
        }
    }

    private var dnsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionOverline(title: "DNS & Privacy")

            HairlinePanel {
                VStack(alignment: .leading, spacing: 0) {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Upstream Resolver")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundStyle(palette.inkPrimary)

                        TextField("1.1.1.1", text: $dnsDraft)
                            .font(.system(size: 14, design: .monospaced))
                            .foregroundStyle(palette.inkPrimary)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled(true)
                            .keyboardType(.URL)
                            .submitLabel(.done)
                            .padding(.horizontal, 12)
                            .frame(minHeight: 44)
                            .background(palette.surfaceRaised)
                            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                            .overlay(
                                RoundedRectangle(cornerRadius: 10, style: .continuous)
                                    .strokeBorder(palette.border, lineWidth: 1)
                            )
                            .onSubmit { commitDns() }
                            .onChange(of: dnsDraft) { newValue in
                                let trimmed = newValue.trimmingCharacters(in: .whitespacesAndNewlines)
                                if !trimmed.isEmpty {
                                    manager.updateSettings { $0.dnsAddr = trimmed }
                                }
                            }

                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 8) {
                                ForEach(dnsPresets, id: \.self) { preset in
                                    let active = manager.settings.dnsAddr == preset
                                    Button {
                                        dnsDraft = preset
                                        manager.updateSettings { $0.dnsAddr = preset }
                                    } label: {
                                        Text(preset)
                                            .font(.system(size: 12, weight: .medium, design: .monospaced))
                                            .foregroundStyle(active ? palette.primaryButtonInk : palette.inkSecondary)
                                            .padding(.horizontal, 10)
                                            .frame(minHeight: 32)
                                            .background(active ? palette.primaryButtonBg : palette.surfaceRaised)
                                            .clipShape(Capsule())
                                            .overlay(
                                                Capsule().strokeBorder(
                                                    active ? Color.clear : palette.border,
                                                    lineWidth: 1
                                                )
                                            )
                                    }
                                    .buttonStyle(.plain)
                                }
                            }
                        }
                    }
                    .padding(14)

                    HairlineRule()

                    toggleRow(
                        title: "DNS-over-HTTPS (RFC 8484)",
                        subtitle: "Sticky multi-provider DoH ring with sinkhole filtering",
                        isOn: Binding(
                            get: { manager.settings.enableDoh },
                            set: { val in manager.updateSettings { $0.enableDoh = val } }
                        )
                    )

                    HairlineRule()

                    toggleRow(
                        title: "Block QUIC (UDP/443)",
                        subtitle: "Drops QUIC Initial packets so apps cleanly use TCP TLS",
                        isOn: Binding(
                            get: { manager.settings.blockQuic },
                            set: { val in manager.updateSettings { $0.blockQuic = val } }
                        )
                    )

                    HairlineRule()

                    toggleRow(
                        title: "IPv4 Only",
                        subtitle: "Disable IPv6 tunnel routing and AAAA queries",
                        isOn: Binding(
                            get: { manager.settings.ipv4Only },
                            set: { val in manager.updateSettings { $0.ipv4Only = val } }
                        )
                    )
                }
            }
        }
    }

    private var tunnelBehaviorSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionOverline(title: "Tunnel Behavior")

            HairlinePanel {
                VStack(spacing: 0) {
                    toggleRow(
                        title: "Connect On-Demand",
                        subtitle: "Automatically keep vdpi active across Wi-Fi and Cellular",
                        isOn: Binding(
                            get: { manager.settings.onDemandEnabled },
                            set: { val in manager.updateSettings { $0.onDemandEnabled = val } }
                        )
                    )
                }
            }
        }
    }

    private var bypassDomainsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionOverline(title: "Domain Bypass")

            HairlinePanel {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Domains here skip TLS fragmentation (LAN, banking, and government portals are already bypassed automatically). Consumer iOS restricts per-app VPN routing to MDM.")
                        .font(.system(size: 12))
                        .foregroundStyle(palette.inkSecondary)
                        .fixedSize(horizontal: false, vertical: true)

                    HStack(spacing: 8) {
                        TextField("e.g. *.example.com", text: $bypassDraft)
                            .font(.system(size: 13, design: .monospaced))
                            .foregroundStyle(palette.inkPrimary)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled(true)
                            .submitLabel(.done)
                            .padding(.horizontal, 12)
                            .frame(minHeight: 44)
                            .background(palette.surfaceRaised)
                            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                            .overlay(
                                RoundedRectangle(cornerRadius: 10, style: .continuous)
                                    .strokeBorder(palette.border, lineWidth: 1)
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
                        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                    }

                    if let bypassError {
                        Text(bypassError)
                            .font(.system(size: 12))
                            .foregroundStyle(palette.danger)
                    }

                    if !manager.settings.bypassDomains.isEmpty {
                        VStack(spacing: 6) {
                            ForEach(manager.settings.bypassDomains, id: \.self) { domain in
                                HStack {
                                    Text(domain)
                                        .font(.system(size: 13, design: .monospaced))
                                        .foregroundStyle(palette.inkPrimary)
                                    Spacer()
                                    Button {
                                        manager.updateSettings {
                                            $0.bypassDomains.removeAll { $0 == domain }
                                        }
                                    } label: {
                                        Image(systemName: "xmark")
                                            .font(.system(size: 12, weight: .semibold))
                                            .foregroundStyle(palette.inkMuted)
                                            .frame(width: 32, height: 32)
                                    }
                                    .buttonStyle(.plain)
                                    .accessibilityLabel("Remove \(domain)")
                                }
                                .padding(.leading, 12)
                                .padding(.trailing, 6)
                                .padding(.vertical, 4)
                                .background(palette.surfaceRaised)
                                .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
                            }
                        }
                    }
                }
                .padding(14)
            }
        }
    }

    private var appearanceSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionOverline(title: "Appearance")

            HairlinePanel {
                HStack(spacing: 8) {
                    ForEach(ThemePreference.allCases) { pref in
                        let selected = manager.settings.theme == pref
                        Button {
                            manager.updateSettings { $0.theme = pref }
                        } label: {
                            Text(pref.label)
                                .font(.system(size: 13, weight: selected ? .semibold : .medium))
                                .frame(maxWidth: .infinity)
                                .frame(minHeight: 40)
                                .foregroundStyle(selected ? palette.primaryButtonInk : palette.inkSecondary)
                                .background(selected ? palette.primaryButtonBg : palette.surfaceRaised)
                                .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(10)
            }
        }
    }

    private func toggleRow(title: String, subtitle: String, isOn: Binding<Bool>) -> some View {
        Toggle(isOn: isOn) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 14, weight: .medium))
                    .foregroundStyle(palette.inkPrimary)
                Text(subtitle)
                    .font(.system(size: 12))
                    .foregroundStyle(palette.inkSecondary)
            }
        }
        .tint(palette.signal)
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
    }

    private func commitDns() {
        let trimmed = dnsDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolved = trimmed.isEmpty ? "1.1.1.1" : trimmed
        dnsDraft = resolved
        manager.updateSettings { $0.dnsAddr = resolved }
    }

    private func addBypassDomain() {
        guard let normalized = VdpiFormatters.normalizeBypassDomain(bypassDraft) else {
            bypassError = "Enter a valid domain such as example.com or *.example.com"
            return
        }
        bypassError = nil
        bypassDraft = ""
        manager.updateSettings { s in
            if !s.bypassDomains.contains(normalized) {
                s.bypassDomains.append(normalized)
                s.bypassDomains.sort()
            }
        }
    }
}
