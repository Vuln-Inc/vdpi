import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

struct ContentView: View {
    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.verticalSizeClass) private var verticalSizeClass
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass

    @State private var selectedTab: VdpiTab = .tunnel
    @State private var bottomSafeInset: CGFloat = 0
    @State private var isKeyboardVisible: Bool = false

    private var isCompactHeight: Bool {
        verticalSizeClass == .compact
    }

    private var contentMaxWidth: CGFloat {
        (isCompactHeight || horizontalSizeClass == .regular) ? 980 : 680
    }

    private var showReconnectPopup: Bool {
        (manager.phase == .connected || manager.phase == .connecting)
            && manager.reconnectPopupVisible
    }

    private var showAccessoryPill: Bool {
        selectedTab == .settings && manager.phase != .disconnected
    }

    private var tabBarBottomOffset: CGFloat {
        if isCompactHeight {
            return max(bottomSafeInset - 6, 8)
        }
        return bottomSafeInset > 0 ? max(bottomSafeInset - 12, 12) : 12
    }

    private var bottomScrimHeight: CGFloat {
        if isCompactHeight {
            return showAccessoryPill
                ? tabBarBottomOffset + 120
                : max(72, tabBarBottomOffset + 72)
        }
        return showAccessoryPill
            ? tabBarBottomOffset + 148
            : max(96, tabBarBottomOffset + 90)
    }

    private var topContentInset: CGFloat {
        guard showReconnectPopup else { return 0 }
        return isCompactHeight ? 62 : 76
    }

    private var bottomContentInset: CGFloat {
        if isCompactHeight {
            return showAccessoryPill
                ? tabBarBottomOffset + 108
                : tabBarBottomOffset + 60
        }
        return showAccessoryPill
            ? tabBarBottomOffset + 136
            : tabBarBottomOffset + 78
    }

    private var popupAnimation: Animation {
        reduceMotion ? .easeInOut(duration: 0.15) : .spring(response: 0.36, dampingFraction: 0.82)
    }

    private var tabLensAnimation: Animation {
        reduceMotion ? .easeInOut(duration: 0.15) : .spring(response: 0.34, dampingFraction: 0.80)
    }

    private var pillAnimation: Animation {
        reduceMotion ? .easeInOut(duration: 0.15) : .easeOut(duration: 0.22)
    }

    private var popupTransition: AnyTransition {
        reduceMotion
            ? .opacity
            : .offset(y: -24).combined(with: .opacity)
    }

    private var bottomItemTransition: AnyTransition {
        reduceMotion
            ? .opacity
            : .offset(y: 12).combined(with: .opacity)
    }

    var body: some View {
        ZStack {
            // Z0: Clean solid Apple canvas background (no ambient orbs or blur)
            palette.canvas
                .ignoresSafeArea()

            // Z0: State-preserving ZStack so scroll offsets and unsaved drafts persist across tabs
            ZStack {
                TunnelView(
                    topInset: topContentInset,
                    bottomInset: bottomContentInset,
                    showInlineReconnect: !showReconnectPopup
                )
                    .vdpiSoftBottomScrollEdge()
                    .opacity(selectedTab == .tunnel ? 1 : 0)
                    .allowsHitTesting(selectedTab == .tunnel)
                    .accessibilityHidden(selectedTab != .tunnel)

                SettingsView(topInset: topContentInset, bottomInset: bottomContentInset)
                    .vdpiSoftBottomScrollEdge()
                    .opacity(selectedTab == .settings ? 1 : 0)
                    .allowsHitTesting(selectedTab == .settings)
                    .accessibilityHidden(selectedTab != .settings)
            }
            .frame(maxWidth: contentMaxWidth, maxHeight: .infinity)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(safeAreaReader)
        // Z10 + Z20: Scroll edge dissolution scrim behind floating bottom chrome
        .overlay(alignment: .bottom) {
            ZStack(alignment: .bottom) {
                ScrollEdgeFadeScrim(height: bottomScrimHeight, fromBottom: true)
                    .opacity(isKeyboardVisible ? 0 : 1)

                bottomDockStack
                    .padding(.bottom, tabBarBottomOffset)
                    .opacity(isKeyboardVisible ? 0 : 1)
                    .offset(y: isKeyboardVisible && !reduceMotion ? 24 : 0)
                    .allowsHitTesting(!isKeyboardVisible)
                    .accessibilityHidden(isKeyboardVisible)
            }
            .ignoresSafeArea(.container, edges: .bottom)
            .ignoresSafeArea(.keyboard, edges: .bottom)
        }
        // Z30: Top-floating "Settings Changed" Liquid Glass popup across all tabs
        .overlay(alignment: .top) {
            if showReconnectPopup {
                TopReconnectPopup(
                    pendingChangeSummary: manager.pendingChangeSummary,
                    isReloading: manager.isReloading,
                    isCompactHeight: isCompactHeight,
                    onReconnect: {
                        manager.applyChangesLive()
                    },
                    onDismiss: {
                        manager.dismissReconnectPopup()
                    }
                )
                .padding(.horizontal, 16)
                .padding(.top, isCompactHeight ? 4 : 8)
                .transition(popupTransition)
            }
        }
        .animation(popupAnimation, value: showReconnectPopup)
        .animation(pillAnimation, value: showAccessoryPill)
        .animation(pillAnimation, value: manager.toastMessage)
        .animation(pillAnimation, value: isKeyboardVisible)
        #if canImport(UIKit)
        .onReceive(NotificationCenter.default.publisher(for: UIResponder.keyboardWillShowNotification)) { notification in
            if let frame = notification.userInfo?[UIResponder.keyboardFrameEndUserInfoKey] as? CGRect {
                isKeyboardVisible = frame.height > 0
            } else {
                isKeyboardVisible = true
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: UIResponder.keyboardWillHideNotification)) { _ in
            isKeyboardVisible = false
        }
        #endif
    }

    // MARK: - Safe Area & Bottom Floating HUD Stack

    private var safeAreaReader: some View {
        GeometryReader { proxy in
            Color.clear
                .onAppear {
                    bottomSafeInset = proxy.safeAreaInsets.bottom
                }
                .vdpiOnChange(of: proxy.safeAreaInsets.bottom) { newInset in
                    bottomSafeInset = newInset
                }
        }
        .ignoresSafeArea(.keyboard, edges: .bottom)
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }

    private var bottomDockStack: some View {
        let stackSpacing: CGFloat = isCompactHeight ? 6 : 8

        return VStack(spacing: stackSpacing) {
            if let toast = manager.toastMessage {
                VdpiToastPill(
                    message: toast,
                    isCompactHeight: isCompactHeight
                )
                .transition(bottomItemTransition)
            }

            VdpiGlassGroupContainer(spacing: stackSpacing) {
                if showAccessoryPill {
                    LiveTunnelAccessoryPill(
                        phase: manager.phase,
                        telemetry: manager.telemetry,
                        errorMessage: manager.errorMessage,
                        isCompactHeight: isCompactHeight,
                        onTapPill: {
                            withAnimation(tabLensAnimation) {
                                selectedTab = .tunnel
                            }
                        },
                        onToggleTunnel: {
                            manager.toggleTunnel()
                        }
                    )
                    .transition(bottomItemTransition)
                }

                FloatingGlassTabBar(
                    selectedTab: $selectedTab,
                    phase: manager.phase,
                    pendingReconnect: manager.pendingReconnect,
                    isCompactHeight: isCompactHeight
                )
                .overlay {
                    if manager.availableUpdate != nil {
                        settingsTabBadgeOverlay
                            .allowsHitTesting(false)
                            .accessibilityHidden(true)
                    }
                }
            }
        }
        .padding(.horizontal, 16)
    }

    private var settingsTabBadgeOverlay: some View {
        HStack(spacing: 0) {
            ForEach(VdpiTab.allCases) { tab in
                if tab == .settings {
                    let isSelected = (selectedTab == .settings)
                    Group {
                        if isCompactHeight {
                            HStack(spacing: 6) {
                                Image(systemName: tab.systemImage(selected: isSelected))
                                    .font(.system(size: 16, weight: .semibold))
                                    .hidden()
                                    .overlay(alignment: .topTrailing) {
                                        Circle()
                                            .fill(palette.accent)
                                            .frame(width: 6, height: 6)
                                            .offset(x: 3, y: -2)
                                    }

                                Text(tab.title)
                                    .font(.caption.weight(isSelected ? .semibold : .medium))
                                    .dynamicTypeSize(...DynamicTypeSize.large)
                                    .lineLimit(1)
                                    .hidden()
                            }
                        } else {
                            VStack(spacing: 3) {
                                Image(systemName: tab.systemImage(selected: isSelected))
                                    .font(.system(size: 20, weight: isSelected ? .semibold : .medium))
                                    .hidden()
                                    .overlay(alignment: .topTrailing) {
                                        Circle()
                                            .fill(palette.accent)
                                            .frame(width: 6, height: 6)
                                            .offset(x: 5, y: -2)
                                    }

                                Text(tab.title)
                                    .font(.caption2.weight(isSelected ? .semibold : .medium))
                                    .dynamicTypeSize(...DynamicTypeSize.large)
                                    .lineLimit(1)
                                    .hidden()
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    Color.clear
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        }
        .padding(isCompactHeight ? 3.5 : 4)
    }
}

// MARK: - Soft Scroll Edge Helper

private extension View {
    @ViewBuilder
    func vdpiSoftBottomScrollEdge() -> some View {
        #if compiler(>=6.2) && os(iOS)
        if #available(iOS 26.0, *) {
            scrollEdgeEffectStyle(.soft, for: .bottom)
        } else {
            self
        }
        #else
        self
        #endif
    }
}
