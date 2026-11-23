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

    // Floating-chrome glass and accent tokens
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

    // Authentic Apple HIG iOS Dark Mode palette
    public static let dark = VdpiPalette(
        isDark: true,
        canvas: Color(hex: 0x000000),
        surface: Color(hex: 0x1C1C1E),
        surfaceRaised: Color(hex: 0x2C2C2E),
        border: Color(hex: 0x38383A),
        borderStrong: Color(hex: 0x48484A),
        inkPrimary: Color(hex: 0xFFFFFF),
        inkSecondary: Color(hex: 0x98989F),
        inkMuted: Color(hex: 0x8E8E93),
        primaryButtonBg: Color(hex: 0x0066CC),
        primaryButtonInk: Color(hex: 0xFFFFFF),
        signal: Color(hex: 0x30D158),
        signalTint: Color(hex: 0x30D158, alpha: 0.15),
        signalBorder: Color(hex: 0x30D158, alpha: 0.35),
        warning: Color(hex: 0xFF9F0A),
        warningTint: Color(hex: 0xFF9F0A, alpha: 0.16),
        danger: Color(hex: 0xFF453A),
        dangerTint: Color(hex: 0xFF453A, alpha: 0.16),
        accent: Color(hex: 0x409CFF),
        accentTint: Color(hex: 0x409CFF, alpha: 0.16),
        glassFill: Color(hex: 0x1C1C1E, alpha: 0.56),
        glassFillElevated: Color(hex: 0x1C1C1E, alpha: 0.68),
        glassFillSubtle: Color(hex: 0x2C2C2E, alpha: 0.45),
        glassLensFill: Color.white.opacity(0.16),
        specularTop: Color.white.opacity(0.24),
        specularMid: Color.white.opacity(0.08),
        specularBottom: Color.white.opacity(0.10),
        innerSheen: Color.white.opacity(0.05),
        shadowColor: Color.black.opacity(0.36),
        signalGlow: .clear,
        warningGlow: .clear,
        dangerGlow: .clear
    )

    // Authentic Apple HIG iOS Light Mode palette
    public static let light = VdpiPalette(
        isDark: false,
        canvas: Color(hex: 0xF2F2F7),
        surface: Color(hex: 0xFFFFFF),
        surfaceRaised: Color(hex: 0xE5E5EA),
        border: Color(hex: 0xC6C6C8),
        borderStrong: Color(hex: 0xAEAEB2),
        inkPrimary: Color(hex: 0x000000),
        inkSecondary: Color(hex: 0x5C5C60),
        inkMuted: Color(hex: 0x6C6C70),
        primaryButtonBg: Color(hex: 0x0066CC),
        primaryButtonInk: Color(hex: 0xFFFFFF),
        signal: Color(hex: 0x1E7E34),
        signalTint: Color(hex: 0x34C759, alpha: 0.12),
        signalBorder: Color(hex: 0x34C759, alpha: 0.30),
        warning: Color(hex: 0xC93400),
        warningTint: Color(hex: 0xFF9500, alpha: 0.12),
        danger: Color(hex: 0xD70015),
        dangerTint: Color(hex: 0xFF3B30, alpha: 0.12),
        accent: Color(hex: 0x0066CC),
        accentTint: Color(hex: 0x0066CC, alpha: 0.12),
        glassFill: Color.white.opacity(0.68),
        glassFillElevated: Color.white.opacity(0.78),
        glassFillSubtle: Color.white.opacity(0.55),
        glassLensFill: Color.black.opacity(0.08),
        specularTop: Color.white.opacity(0.88),
        specularMid: Color.black.opacity(0.06),
        specularBottom: Color.black.opacity(0.10),
        innerSheen: Color.white.opacity(0.32),
        shadowColor: Color.black.opacity(0.10),
        signalGlow: .clear,
        warningGlow: .clear,
        dangerGlow: .clear
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
                    .init(color: accent.opacity(isDark ? 0.34 : 0.26), location: 0.0),
                    .init(color: specularTop.opacity(isDark ? 0.65 : 0.72), location: 0.28),
                    .init(color: specularMid, location: 0.62),
                    .init(color: accent.opacity(isDark ? 0.16 : 0.14), location: 1.0),
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        }
        return LinearGradient(
            stops: [
                .init(color: specularTop, location: 0.0),
                .init(color: specularMid, location: 0.50),
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
                .init(color: innerSheen.opacity(0.20), location: 0.24),
                .init(color: .clear, location: 0.52),
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
