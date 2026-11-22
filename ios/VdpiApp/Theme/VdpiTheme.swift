import SwiftUI

public struct VdpiPalette: Equatable, Sendable {
    public let isDark: Bool
    public let canvas: Color
    public let surface: Color
    public let surfaceRaised: Color
    public let border: Color
    public let borderStrong: Color
    public let inkPrimary: Color
    public let inkSecondary: Color
    public let inkMuted: Color
    public let primaryButtonBg: Color
    public let primaryButtonInk: Color
    public let signal: Color
    public let signalTint: Color
    public let signalBorder: Color
    public let warning: Color
    public let warningTint: Color
    public let danger: Color
    public let dangerTint: Color

    public static let dark = VdpiPalette(
        isDark: true,
        canvas: Color(hex: 0x09090B),
        surface: Color(hex: 0x111113),
        surfaceRaised: Color(hex: 0x18181B),
        border: Color.white.opacity(0.10),
        borderStrong: Color.white.opacity(0.20),
        inkPrimary: Color(hex: 0xF4F4F5),
        inkSecondary: Color(hex: 0xA1A1AA),
        inkMuted: Color(hex: 0x8E8E9A),
        primaryButtonBg: Color(hex: 0xF4F4F5),
        primaryButtonInk: Color(hex: 0x09090B),
        signal: Color(hex: 0x10B981),
        signalTint: Color(hex: 0x10B981, alpha: 0.12),
        signalBorder: Color(hex: 0x10B981, alpha: 0.34),
        warning: Color(hex: 0xF59E0B),
        warningTint: Color(hex: 0xF59E0B, alpha: 0.12),
        danger: Color(hex: 0xF87171),
        dangerTint: Color(hex: 0xF87171, alpha: 0.14)
    )

    public static let light = VdpiPalette(
        isDark: false,
        canvas: Color(hex: 0xFAFAFA),
        surface: Color(hex: 0xFFFFFF),
        surfaceRaised: Color(hex: 0xF4F4F5),
        border: Color(hex: 0xD4D4D8),
        borderStrong: Color(hex: 0xA1A1AA),
        inkPrimary: Color(hex: 0x09090B),
        inkSecondary: Color(hex: 0x52525B),
        inkMuted: Color(hex: 0x5C5C66),
        primaryButtonBg: Color(hex: 0x09090B),
        primaryButtonInk: Color(hex: 0xFAFAFA),
        signal: Color(hex: 0x047857),
        signalTint: Color(hex: 0x047857, alpha: 0.09),
        signalBorder: Color(hex: 0x047857, alpha: 0.34),
        warning: Color(hex: 0x9A3412),
        warningTint: Color(hex: 0x9A3412, alpha: 0.10),
        danger: Color(hex: 0xB91C1C),
        dangerTint: Color(hex: 0xB91C1C, alpha: 0.10)
    )

    public static func resolve(
        preference: ThemePreference,
        systemScheme: ColorScheme
    ) -> VdpiPalette {
        switch preference {
        case .dark: return .dark
        case .light: return .light
        case .system: return systemScheme == .dark ? .dark : .light
        }
    }
}

public extension Color {
    init(hex: UInt32, alpha: Double = 1.0) {
        let r = Double((hex >> 16) & 0xFF) / 255.0
        let g = Double((hex >> 8) & 0xFF) / 255.0
        let b = Double(hex & 0xFF) / 255.0
        self.init(.sRGB, red: r, green: g, blue: b, opacity: alpha)
    }
}

private struct VdpiPaletteKey: EnvironmentKey {
    static let defaultValue: VdpiPalette = .dark
}

public extension EnvironmentValues {
    var vdpiPalette: VdpiPalette {
        get { self[VdpiPaletteKey.self] }
        set { self[VdpiPaletteKey.self] = newValue }
    }
}

public extension ThemePreference {
    var preferredColorScheme: ColorScheme? {
        switch self {
        case .system: return nil
        case .dark: return .dark
        case .light: return .light
        }
    }
}
