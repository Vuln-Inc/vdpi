import SwiftUI

enum VdpiTab: String, CaseIterable, Identifiable {
    case tunnel
    case settings

    var id: String { rawValue }

    var title: String {
        switch self {
        case .tunnel: return "Tunnel"
        case .settings: return "Settings"
        }
    }

    var systemImage: String {
        switch self {
        case .tunnel: return "shield.lefthalf.filled"
        case .settings: return "slider.horizontal.3"
        }
    }
}

struct ContentView: View {
    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette
    @State private var selectedTab: VdpiTab = .tunnel

    var body: some View {
        ZStack(alignment: .bottom) {
            palette.canvas
                .ignoresSafeArea()

            VStack(spacing: 0) {
                ZStack {
                    TunnelView()
                        .opacity(selectedTab == .tunnel ? 1 : 0)
                        .allowsHitTesting(selectedTab == .tunnel)
                        .accessibilityHidden(selectedTab != .tunnel)
                    SettingsView()
                        .opacity(selectedTab == .settings ? 1 : 0)
                        .allowsHitTesting(selectedTab == .settings)
                        .accessibilityHidden(selectedTab != .settings)
                }
                .frame(maxWidth: 680, maxHeight: .infinity)
                .frame(maxWidth: .infinity, maxHeight: .infinity)

                HairlineRule()

                HStack(spacing: 8) {
                    ForEach(VdpiTab.allCases) { tab in
                        let isSelected = (selectedTab == tab)
                        Button {
                            withAnimation(.easeOut(duration: 0.16)) {
                                selectedTab = tab
                            }
                        } label: {
                            HStack(spacing: 7) {
                                Image(systemName: tab.systemImage)
                                    .font(.system(size: 14, weight: isSelected ? .semibold : .regular))
                                Text(tab.title)
                                    .font(.system(size: 13, weight: isSelected ? .semibold : .medium))
                            }
                            .frame(maxWidth: .infinity)
                            .frame(minHeight: 44)
                            .foregroundStyle(isSelected ? palette.inkPrimary : palette.inkMuted)
                            .background(
                                isSelected ? palette.surfaceRaised : Color.clear
                            )
                            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                            .overlay(
                                RoundedRectangle(cornerRadius: 10, style: .continuous)
                                    .strokeBorder(
                                        isSelected ? palette.border : Color.clear,
                                        lineWidth: 1
                                    )
                            )
                        }
                        .buttonStyle(VdpiPressButtonStyle())
                        .accessibilityAddTraits(isSelected ? .isSelected : [])
                    }
                }
                .frame(maxWidth: 680)
                .padding(.horizontal, 16)
                .padding(.top, 10)
                .padding(.bottom, 10)
                .frame(maxWidth: .infinity)
                .background(palette.surface)
            }
            .ignoresSafeArea(.keyboard, edges: .bottom)

            if let toast = manager.toastMessage {
                Text(toast)
                    .font(.system(size: 13, weight: .medium))
                    .multilineTextAlignment(.center)
                    .foregroundStyle(palette.primaryButtonInk)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                    .background(palette.primaryButtonBg)
                    .clipShape(Capsule())
                    .shadow(color: Color.black.opacity(0.25), radius: 10, y: 4)
                    .padding(.horizontal, 20)
                    .padding(.bottom, 76)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(.easeInOut(duration: 0.2), value: manager.toastMessage)
    }
}
