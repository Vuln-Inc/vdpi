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

    // Liquid Glass tokens
    public let accent: Color
    public let accentTint: Color
    public let glassFill: Color
    public let glassFillElevated: Color
    public let glassFillSubtle: Color
    public let glassLensFill: Color
    public let specularTop: Color
    public let specularMid: Color
    public let specularBottom: Color
    public let innerSheen: Color
    public let shadowColor: Color
    public let signalGlow: Color
    public let warningGlow: Color
    public let dangerGlow: Color

    public static let dark = VdpiPalette(
        isDark: true,
        canvas: Color(hex: 0x000000),
        surface: Color(hex: 0x0D0E12),
        surfaceRaised: Color(hex: 0x181A20),
        border: Color.white.opacity(0.11),
        borderStrong: Color.white.opacity(0.22),
        inkPrimary: Color(hex: 0xFFFFFF),
        inkSecondary: Color(hex: 0xA1A8B3),
        inkMuted: Color(hex: 0x7C8594),
        primaryButtonBg: Color(hex: 0xFFFFFF),
        primaryButtonInk: Color(hex: 0x06080D),
        signal: Color(hex: 0x10E896),
        signalTint: Color(hex: 0x10E896, alpha: 0.14),
        signalBorder: Color(hex: 0x10E896, alpha: 0.38),
        warning: Color(hex: 0xF59E0B),
        warningTint: Color(hex: 0xF59E0B, alpha: 0.14),
        danger: Color(hex: 0xFF4D6D),
        dangerTint: Color(hex: 0xFF4D6D, alpha: 0.15),
        accent: Color(hex: 0x19C8FF),
        accentTint: Color(hex: 0x19C8FF, alpha: 0.14),
        glassFill: Color(hex: 0x141720, alpha: 0.54),
        glassFillElevated: Color(hex: 0x1D212E, alpha: 0.68),
        glassFillSubtle: Color(hex: 0x0F1118, alpha: 0.38),
        glassLensFill: Color.white.opacity(0.14),
        specularTop: Color.white.opacity(0.32),
        specularMid: Color.white.opacity(0.08),
        specularBottom: Color.white.opacity(0.14),
        innerSheen: Color.white.opacity(0.11),
        shadowColor: Color.black.opacity(0.55),
        signalGlow: Color(hex: 0x10E896, alpha: 0.42),
        warningGlow: Color(hex: 0xF59E0B, alpha: 0.38),
        dangerGlow: Color(hex: 0xFF4D6D, alpha: 0.42)
    )

    public static let light = VdpiPalette(
        isDark: false,
        canvas: Color(hex: 0xF4F7FA),
        surface: Color(hex: 0xFFFFFF),
        surfaceRaised: Color(hex: 0xEAEFF5),
        border: Color(hex: 0x0A0F1A, alpha: 0.10),
        borderStrong: Color(hex: 0x0A0F1A, alpha: 0.20),
        inkPrimary: Color(hex: 0x0A0F1A),
        inkSecondary: Color(hex: 0x4B5565),
        inkMuted: Color(hex: 0x64748B),
        primaryButtonBg: Color(hex: 0x0A0F1A),
        primaryButtonInk: Color(hex: 0xFFFFFF),
        signal: Color(hex: 0x059669),
        signalTint: Color(hex: 0x059669, alpha: 0.11),
        signalBorder: Color(hex: 0x059669, alpha: 0.34),
        warning: Color(hex: 0xD97706),
        warningTint: Color(hex: 0xD97706, alpha: 0.11),
        danger: Color(hex: 0xE11D48),
        dangerTint: Color(hex: 0xE11D48, alpha: 0.11),
        accent: Color(hex: 0x0284C7),
        accentTint: Color(hex: 0x0284C7, alpha: 0.11),
        glassFill: Color.white.opacity(0.64),
        glassFillElevated: Color.white.opacity(0.80),
        glassFillSubtle: Color(hex: 0xEAEFF5, alpha: 0.56),
        glassLensFill: Color.white.opacity(0.86),
        specularTop: Color.white.opacity(0.92),
        specularMid: Color(hex: 0x0A0F1A, alpha: 0.07),
        specularBottom: Color(hex: 0x0A0F1A, alpha: 0.12),
        innerSheen: Color.white.opacity(0.55),
        shadowColor: Color(hex: 0x0A0F1A, alpha: 0.09),
        signalGlow: Color(hex: 0x059669, alpha: 0.30),
        warningGlow: Color(hex: 0xD97706, alpha: 0.28),
        dangerGlow: Color(hex: 0xE11D48, alpha: 0.30)
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

    public func specularRim(accent: Color? = nil) -> LinearGradient {
        if let accent {
            return LinearGradient(
                stops: [
                    .init(color: accent.opacity(isDark ? 0.68 : 0.58), location: 0.0),
                    .init(color: specularTop.opacity(isDark ? 0.85 : 0.90), location: 0.26),
                    .init(color: specularMid, location: 0.58),
                    .init(color: accent.opacity(isDark ? 0.34 : 0.28), location: 1.0),
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        }
        return LinearGradient(
            stops: [
                .init(color: specularTop, location: 0.0),
                .init(color: specularMid, location: 0.46),
                .init(color: specularBottom, location: 1.0),
            ],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }

    public var topSheenGradient: LinearGradient {
        LinearGradient(
            stops: [
                .init(color: innerSheen, location: 0.0),
                .init(color: innerSheen.opacity(0.28), location: 0.32),
                .init(color: .clear, location: 0.68),
            ],
            startPoint: .top,
            endPoint: .bottom
        )
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
