import SwiftUI

@main
struct VdpiApp: App {
    @StateObject private var manager = TunnelManager()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ThemedRootView()
                .environmentObject(manager)
                .preferredColorScheme(manager.settings.theme.preferredColorScheme)
                .vdpiOnChange(of: scenePhase) { newPhase in
                    manager.setSceneActive(newPhase == .active)
                }
        }
    }
}

private struct ThemedRootView: View {
    @EnvironmentObject private var manager: TunnelManager
    @Environment(\.colorScheme) private var systemScheme

    var body: some View {
        let palette = VdpiPalette.resolve(
            preference: manager.settings.theme,
            systemScheme: systemScheme
        )
        ContentView()
            .environment(\.vdpiPalette, palette)
    }
}
