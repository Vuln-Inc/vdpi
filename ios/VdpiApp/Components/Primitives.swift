import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

// MARK: - Motion & Haptics

enum VdpiMotion {
    static let tabLens = Animation.spring(response: 0.34, dampingFraction: 0.76)
    static let floatingHud = Animation.spring(response: 0.38, dampingFraction: 0.78)
    static let cardShift = Animation.spring(response: 0.38, dampingFraction: 0.84)
    static let press = Animation.spring(response: 0.22, dampingFraction: 0.78)
    static let dismiss = Animation.spring(response: 0.26, dampingFraction: 1.0)
}

@MainActor
enum VdpiHaptics {
    enum Kind: Equatable, Sendable {
        case light
        case medium
        case selection
        case success
        case warning
    }

    static func trigger(_ kind: Kind) {
        #if canImport(UIKit)
        switch kind {
        case .light:
            let generator = UIImpactFeedbackGenerator(style: .light)
            generator.prepare()
            generator.impactOccurred()
        case .medium:
            let generator = UIImpactFeedbackGenerator(style: .medium)
            generator.prepare()
            generator.impactOccurred()
        case .selection:
            let generator = UISelectionFeedbackGenerator()
            generator.prepare()
            generator.selectionChanged()
        case .success:
            let generator = UINotificationFeedbackGenerator()
            generator.prepare()
            generator.notificationOccurred(.success)
        case .warning:
            let generator = UINotificationFeedbackGenerator()
            generator.prepare()
            generator.notificationOccurred(.warning)
        }
        #endif
    }
}

// MARK: - Compatibility Helpers

extension View {
    @ViewBuilder
    func vdpiOnChange<V: Equatable>(
        of value: V,
        perform action: @escaping (V) -> Void
    ) -> some View {
        if #available(iOS 17.0, *) {
            onChange(of: value) { _, newValue in
                action(newValue)
            }
        } else {
            onChange(of: value, perform: action)
        }
    }
}

// MARK: - Liquid Glass Surface

enum VdpiGlassTier: Equatable, Sendable {
    case subtle
    case regular
    case elevated
}

struct VdpiGlassSurfaceModifier<S: InsettableShape>: ViewModifier {
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    let shape: S
    let tier: VdpiGlassTier
    let tint: Color?
    let borderAccent: Color?
    let interactive: Bool

    func body(content: Content) -> some View {
        if reduceTransparency {
            reducedTransparencySurface(for: content)
        } else {
            #if compiler(>=6.2) && os(iOS)
            if #available(iOS 26.0, *) {
                nativeLiquidGlass(for: content)
            } else {
                fallbackLiquidGlass(for: content)
            }
            #else
            fallbackLiquidGlass(for: content)
            #endif
        }
    }

    #if compiler(>=6.2) && os(iOS)
    @available(iOS 26.0, *)
    private func nativeLiquidGlass(for content: Content) -> some View {
        let baseGlass: Glass = tier == .subtle ? .clear : .regular
        let tintedGlass: Glass = tint.map { baseGlass.tint($0) } ?? baseGlass
        let resolvedGlass: Glass = interactive ? tintedGlass.interactive() : tintedGlass

        return content
            .glassEffect(resolvedGlass, in: shape)
            .overlay {
                if let borderAccent {
                    shape
                        .strokeBorder(
                            palette.specularRim(accent: borderAccent),
                            lineWidth: 0.85
                        )
                        .allowsHitTesting(false)
                }
            }
    }
    #endif

    private func fallbackLiquidGlass(for content: Content) -> some View {
        content
            .background {
                ZStack {
                    shape.fill(materialForTier)
                    shape.fill(fillForTier)
                    if let tint {
                        shape.fill(tint)
                    }
                    shape.fill(palette.topSheenGradient)
                }
            }
            .clipShape(shape)
            .overlay {
                shape
                    .strokeBorder(
                        palette.specularRim(accent: borderAccent),
                        lineWidth: borderAccent == nil ? 0.85 : 1.0
                    )
                    .allowsHitTesting(false)
            }
            .shadow(
                color: shadowColorForTier,
                radius: shadowRadiusForTier,
                x: 0,
                y: shadowYOffsetForTier
            )
    }

    private func reducedTransparencySurface(for content: Content) -> some View {
        content
            .background {
                ZStack {
                    shape.fill(tier == .elevated ? palette.surfaceRaised : palette.surface)
                    if let tint {
                        shape.fill(tint)
                    }
                }
            }
            .clipShape(shape)
            .overlay {
                shape
                    .strokeBorder(borderAccent ?? palette.borderStrong, lineWidth: 1)
                    .allowsHitTesting(false)
            }
            .shadow(
                color: tier == .subtle ? .clear : shadowColorForTier,
                radius: tier == .subtle ? 0 : shadowRadiusForTier * 0.7,
                x: 0,
                y: tier == .subtle ? 0 : shadowYOffsetForTier * 0.7
            )
    }

    private var materialForTier: Material {
        switch tier {
        case .subtle, .regular:
            return .ultraThinMaterial
        case .elevated:
            return .thinMaterial
        }
    }

    private var fillForTier: Color {
        switch tier {
        case .subtle:
            return palette.glassFillSubtle
        case .regular:
            return palette.glassFill
        case .elevated:
            return palette.glassFillElevated
        }
    }

    private var shadowColorForTier: Color {
        switch tier {
        case .subtle:
            return palette.shadowColor.opacity(0.35)
        case .regular:
            return palette.shadowColor
        case .elevated:
            return palette.shadowColor
        }
    }

    private var shadowRadiusForTier: CGFloat {
        switch tier {
        case .subtle:
            return 6
        case .regular:
            return 14
        case .elevated:
            return 22
        }
    }

    private var shadowYOffsetForTier: CGFloat {
        switch tier {
        case .subtle:
            return 2
        case .regular:
            return 6
        case .elevated:
            return 10
        }
    }
}

extension View {
    func vdpiGlass<S: InsettableShape>(
        in shape: S,
        tier: VdpiGlassTier = .regular,
        tint: Color? = nil,
        borderAccent: Color? = nil,
        interactive: Bool = false
    ) -> some View {
        modifier(
            VdpiGlassSurfaceModifier(
                shape: shape,
                tier: tier,
                tint: tint,
                borderAccent: borderAccent,
                interactive: interactive
            )
        )
    }
}

// MARK: - Glass Containers & Buttons

struct GlassPanel<Content: View>: View {
    var cornerRadius: CGFloat = 22
    var tier: VdpiGlassTier = .regular
    var tint: Color? = nil
    var borderAccent: Color? = nil
    @ViewBuilder let content: () -> Content

    var body: some View {
        content()
            .vdpiGlass(
                in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous),
                tier: tier,
                tint: tint,
                borderAccent: borderAccent
            )
    }
}

struct GlassCircleButton: View {
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    let systemImage: String
    let accessibilityLabel: String
    let tint: Color?
    let badgeColor: Color?
    let isSpinning: Bool
    let action: () -> Void

    @State private var spinPhase: Bool = false

    init(
        systemImage: String,
        accessibilityLabel: String,
        tint: Color? = nil,
        badgeColor: Color? = nil,
        isSpinning: Bool = false,
        action: @escaping () -> Void
    ) {
        self.systemImage = systemImage
        self.accessibilityLabel = accessibilityLabel
        self.tint = tint
        self.badgeColor = badgeColor
        self.isSpinning = isSpinning
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            ZStack(alignment: .topTrailing) {
                Image(systemName: systemImage)
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(tint ?? palette.inkPrimary)
                    .rotationEffect(.degrees(spinPhase ? 360 : 0))
                    .animation(
                        spinPhase
                            ? .linear(duration: 1.0).repeatForever(autoreverses: false)
                            : .easeOut(duration: 0.2),
                        value: spinPhase
                    )
                    .frame(width: 44, height: 44)
                    .vdpiGlass(
                        in: Circle(),
                        tier: .regular,
                        tint: tint.map { $0.opacity(palette.isDark ? 0.14 : 0.10) },
                        borderAccent: tint.map { $0.opacity(0.45) },
                        interactive: true
                    )

                if let badgeColor {
                    Circle()
                        .fill(badgeColor)
                        .frame(width: 9, height: 9)
                        .overlay(
                            Circle()
                                .strokeBorder(palette.canvas, lineWidth: 1.5)
                        )
                        .shadow(color: badgeColor.opacity(0.55), radius: 4, x: 0, y: 0)
                        .offset(x: -2, y: 2)
                }
            }
        }
        .buttonStyle(VdpiPressButtonStyle(haptic: .light))
        .accessibilityLabel(accessibilityLabel)
        .onAppear {
            spinPhase = isSpinning && !reduceMotion
        }
        .vdpiOnChange(of: isSpinning) { spinning in
            spinPhase = spinning && !reduceMotion
        }
        .vdpiOnChange(of: reduceMotion) { reduced in
            spinPhase = isSpinning && !reduced
        }
    }
}

// MARK: - Ambient & Hero Backdrops

struct OrganicMeshHeroBackdrop: View {
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    let phase: TunnelPhase
    let isSceneActive: Bool

    init(phase: TunnelPhase, isSceneActive: Bool) {
        self.phase = phase
        self.isSceneActive = isSceneActive
    }

    private var shouldAnimate: Bool {
        isSceneActive && !reduceMotion
    }

    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 30.0, paused: !shouldAnimate)) { timeline in
            let t: TimeInterval = shouldAnimate ? timeline.date.timeIntervalSinceReferenceDate : 0.0
            let colors = auroraColors

            ZStack {
                if #available(iOS 18.0, *) {
                    meshAurora(time: t, colors: colors)
                } else {
                    radialAuroraFallback(time: t, colors: colors)
                }

                // Subtle contrast veil so hero typography remains crisp over luminous aurora peaks
                LinearGradient(
                    stops: [
                        .init(
                            color: palette.isDark
                                ? Color.black.opacity(0.14)
                                : Color.white.opacity(0.24),
                            location: 0.0
                        ),
                        .init(
                            color: palette.isDark
                                ? Color.black.opacity(0.32)
                                : Color.white.opacity(0.36),
                            location: 1.0
                        ),
                    ],
                    startPoint: .top,
                    endPoint: .bottom
                )
            }
        }
        .animation(VdpiMotion.cardShift, value: phase)
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }

    @available(iOS 18.0, *)
    private func meshAurora(time t: TimeInterval, colors: [Color]) -> some View {
        let dx0 = Float(sin(t * 0.42) * 0.16)
        let dx1 = Float(cos(t * 0.36 + 0.9) * 0.16)
        let dy0 = Float(cos(t * 0.38) * 0.14)
        let dy1 = Float(sin(t * 0.44 + 1.4) * 0.14)
        let cx = Float(sin(t * 0.31 + 0.5) * 0.18)
        let cy = Float(cos(t * 0.27 + 1.1) * 0.16)

        let points: [SIMD2<Float>] = [
            SIMD2<Float>(0.0, 0.0),
            SIMD2<Float>(0.5 + dx0, 0.0),
            SIMD2<Float>(1.0, 0.0),
            SIMD2<Float>(0.0, 0.5 + dy0),
            SIMD2<Float>(0.5 + cx, 0.5 + cy),
            SIMD2<Float>(1.0, 0.5 + dy1),
            SIMD2<Float>(0.0, 1.0),
            SIMD2<Float>(0.5 + dx1, 1.0),
            SIMD2<Float>(1.0, 1.0),
        ]

        return MeshGradient(
            width: 3,
            height: 3,
            points: points,
            colors: colors,
            smoothsColors: true
        )
    }

    private func radialAuroraFallback(time t: TimeInterval, colors: [Color]) -> some View {
        let p1 = UnitPoint(
            x: 0.24 + sin(t * 0.38) * 0.14,
            y: 0.22 + cos(t * 0.31) * 0.12
        )
        let p2 = UnitPoint(
            x: 0.78 + cos(t * 0.34 + 1.1) * 0.14,
            y: 0.32 + sin(t * 0.41 + 0.7) * 0.14
        )
        let p3 = UnitPoint(
            x: 0.52 + sin(t * 0.29 + 2.0) * 0.18,
            y: 0.82 + cos(t * 0.33 + 1.5) * 0.10
        )

        return ZStack {
            LinearGradient(
                colors: [colors[0], colors[6], colors[8]],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )

            RadialGradient(
                colors: [colors[4].opacity(0.85), colors[4].opacity(0.25), .clear],
                center: p1,
                startRadius: 8,
                endRadius: 230
            )

            RadialGradient(
                colors: [colors[2].opacity(0.80), colors[2].opacity(0.20), .clear],
                center: p2,
                startRadius: 10,
                endRadius: 240
            )

            RadialGradient(
                colors: [colors[7].opacity(0.75), colors[5].opacity(0.20), .clear],
                center: p3,
                startRadius: 12,
                endRadius: 220
            )
        }
    }

    private var auroraColors: [Color] {
        switch phase {
        case .connected:
            if palette.isDark {
                return [
                    Color(hex: 0x06283D), Color(hex: 0x043B4E), Color(hex: 0x00C2D1),
                    Color(hex: 0x052E3A), Color(hex: 0x00D26A), Color(hex: 0x064E5B),
                    Color(hex: 0x03131E), Color(hex: 0x06283D), Color(hex: 0x05383F),
                ]
            } else {
                return [
                    Color(hex: 0xD2F5E8), Color(hex: 0xCCF4F2), Color(hex: 0xB8ECF5),
                    Color(hex: 0xDCF9EE), Color(hex: 0x99EAC6), Color(hex: 0xC4F1F9),
                    Color(hex: 0xECFAF5), Color(hex: 0xD6F6EE), Color(hex: 0xE1F4FA),
                ]
            }

        case .connecting, .disconnecting:
            if palette.isDark {
                return [
                    Color(hex: 0x1A1308), Color(hex: 0x5C3608), Color(hex: 0x06283D),
                    Color(hex: 0x3D2507), Color(hex: 0xF59E0B), Color(hex: 0x00C2D1),
                    Color(hex: 0x120E09), Color(hex: 0x2B1E0B), Color(hex: 0x082A38),
                ]
            } else {
                return [
                    Color(hex: 0xFEF3C7), Color(hex: 0xFDE68A), Color(hex: 0xCFFAFE),
                    Color(hex: 0xFFF7DB), Color(hex: 0xFCD34D), Color(hex: 0xBAE6FD),
                    Color(hex: 0xFFFBEB), Color(hex: 0xFEF0C7), Color(hex: 0xE0F2FE),
                ]
            }

        case .error:
            if palette.isDark {
                return [
                    Color(hex: 0x240710), Color(hex: 0x5E0D24), Color(hex: 0x3B0A16),
                    Color(hex: 0x450B1C), Color(hex: 0xFF4D6D), Color(hex: 0x881337),
                    Color(hex: 0x14050A), Color(hex: 0x300814), Color(hex: 0x1F060E),
                ]
            } else {
                return [
                    Color(hex: 0xFFE4E6), Color(hex: 0xFECDD3), Color(hex: 0xFFE8EC),
                    Color(hex: 0xFFF1F2), Color(hex: 0xFDA4AF), Color(hex: 0xFECDD3),
                    Color(hex: 0xFFF5F6), Color(hex: 0xFFE4E8), Color(hex: 0xFDE2E8),
                ]
            }

        case .disconnected:
            if palette.isDark {
                return [
                    Color(hex: 0x05070B), Color(hex: 0x111827), Color(hex: 0x0B1320),
                    Color(hex: 0x0D1117), Color(hex: 0x1E293B), Color(hex: 0x111622),
                    Color(hex: 0x000000), Color(hex: 0x0C1018), Color(hex: 0x080B11),
                ]
            } else {
                return [
                    Color(hex: 0xF4F7FA), Color(hex: 0xE2E8F0), Color(hex: 0xEEF2F6),
                    Color(hex: 0xEDF2F7), Color(hex: 0xCBD5E1), Color(hex: 0xE6ECF2),
                    Color(hex: 0xF8FAFC), Color(hex: 0xE8EEF5), Color(hex: 0xF1F5F9),
                ]
            }
        }
    }
}

struct VdpiAmbientBackdrop: View {
    @Environment(\.vdpiPalette) private var palette
    let phase: TunnelPhase

    var body: some View {
        ZStack {
            palette.canvas

            RadialGradient(
                colors: [primaryGlow, .clear],
                center: UnitPoint(x: 0.16, y: 0.08),
                startRadius: 16,
                endRadius: 340
            )

            RadialGradient(
                colors: [secondaryGlow, .clear],
                center: UnitPoint(x: 0.88, y: 0.24),
                startRadius: 20,
                endRadius: 320
            )

            RadialGradient(
                colors: [tertiaryGlow, .clear],
                center: UnitPoint(x: 0.50, y: 0.92),
                startRadius: 10,
                endRadius: 300
            )
        }
        .ignoresSafeArea()
        .animation(VdpiMotion.cardShift, value: phase)
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }

    private var primaryGlow: Color {
        switch phase {
        case .connected:
            return palette.signal.opacity(palette.isDark ? 0.20 : 0.16)
        case .connecting, .disconnecting:
            return palette.warning.opacity(palette.isDark ? 0.18 : 0.14)
        case .error:
            return palette.danger.opacity(palette.isDark ? 0.20 : 0.15)
        case .disconnected:
            return palette.accent.opacity(palette.isDark ? 0.08 : 0.09)
        }
    }

    private var secondaryGlow: Color {
        switch phase {
        case .connected:
            return palette.accent.opacity(palette.isDark ? 0.16 : 0.13)
        case .connecting, .disconnecting:
            return palette.accent.opacity(palette.isDark ? 0.14 : 0.11)
        case .error:
            return Color(hex: 0x9F1239, alpha: palette.isDark ? 0.16 : 0.10)
        case .disconnected:
            return (palette.isDark ? Color(hex: 0x334155) : Color(hex: 0x94A3B8))
                .opacity(palette.isDark ? 0.12 : 0.16)
        }
    }

    private var tertiaryGlow: Color {
        switch phase {
        case .connected:
            return Color(hex: 0x06283D, alpha: palette.isDark ? 0.26 : 0.08)
        case .connecting, .disconnecting:
            return palette.warning.opacity(palette.isDark ? 0.08 : 0.06)
        case .error:
            return palette.danger.opacity(palette.isDark ? 0.10 : 0.07)
        case .disconnected:
            return Color.clear
        }
    }
}

// MARK: - Upgraded Core Primitives

struct HairlinePanel<Content: View>: View {
    var borderColor: Color? = nil
    var backgroundColor: Color? = nil
    var cornerRadius: CGFloat = 18
    @ViewBuilder let content: () -> Content

    var body: some View {
        GlassPanel(
            cornerRadius: cornerRadius,
            tier: .regular,
            tint: backgroundColor,
            borderAccent: borderColor,
            content: content
        )
    }
}

struct HairlineRule: View {
    @Environment(\.vdpiPalette) private var palette

    var body: some View {
        Rectangle()
            .fill(
                LinearGradient(
                    stops: [
                        .init(color: palette.border.opacity(0.25), location: 0.0),
                        .init(
                            color: palette.isDark ? Color.white.opacity(0.15) : palette.border,
                            location: 0.5
                        ),
                        .init(color: palette.border.opacity(0.25), location: 1.0),
                    ],
                    startPoint: .leading,
                    endPoint: .trailing
                )
            )
            .frame(height: 0.75)
    }
}

struct VdpiPressButtonStyle: ButtonStyle {
    var haptic: VdpiHaptics.Kind? = .light

    init(haptic: VdpiHaptics.Kind? = .light) {
        self.haptic = haptic
    }

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.965 : 1.0)
            .opacity(configuration.isPressed ? 0.88 : 1.0)
            .animation(VdpiMotion.press, value: configuration.isPressed)
            .vdpiOnChange(of: configuration.isPressed) { isPressed in
                if isPressed, let haptic {
                    Task { @MainActor in
                        VdpiHaptics.trigger(haptic)
                    }
                }
            }
    }
}

struct SectionOverline: View {
    @Environment(\.vdpiPalette) private var palette
    let title: String

    var body: some View {
        Text(title.uppercased())
            .font(.system(size: 11, weight: .semibold, design: .monospaced))
            .tracking(0.9)
            .foregroundStyle(palette.inkMuted)
            .accessibilityAddTraits(.isHeader)
    }
}

/// Signature fractured-V geometric brand emblem matching the Android app.
struct VdpiBrandMark: View {
    @Environment(\.vdpiPalette) private var palette
    var isActive: Bool = true

    init(isActive: Bool = true) {
        self.isActive = isActive
    }

    var body: some View {
        ZStack {
            Canvas { ctx, size in
                let w = size.width
                let h = size.height
                // Left V stroke (solid)
                var left = Path()
                left.move(to: CGPoint(x: w * 0.22, y: h * 0.26))
                left.addLine(to: CGPoint(x: w * 0.48, y: h * 0.74))
                ctx.stroke(
                    left,
                    with: .color(palette.inkPrimary),
                    style: StrokeStyle(lineWidth: 2.3, lineCap: .round)
                )
                // Right V stroke (fractured into 2 desynced segments)
                var rightBottom = Path()
                rightBottom.move(to: CGPoint(x: w * 0.50, y: h * 0.74))
                rightBottom.addLine(to: CGPoint(x: w * 0.62, y: h * 0.52))
                ctx.stroke(
                    rightBottom,
                    with: .color(palette.inkPrimary),
                    style: StrokeStyle(lineWidth: 2.3, lineCap: .round)
                )
                var rightTop = Path()
                rightTop.move(to: CGPoint(x: w * 0.69, y: h * 0.39))
                rightTop.addLine(to: CGPoint(x: w * 0.78, y: h * 0.26))
                ctx.stroke(
                    rightTop,
                    with: .color(isActive ? palette.signal : palette.inkMuted),
                    style: StrokeStyle(lineWidth: 2.3, lineCap: .round)
                )
            }
            .frame(width: 22, height: 22)
        }
        .frame(width: 32, height: 32)
        .vdpiGlass(
            in: RoundedRectangle(cornerRadius: 9, style: .continuous),
            tier: .elevated,
            tint: isActive ? palette.signalTint : nil,
            borderAccent: isActive ? palette.signal.opacity(0.55) : nil
        )
        .shadow(
            color: isActive ? palette.signalGlow : .clear,
            radius: 10,
            x: 0,
            y: 2
        )
        .animation(VdpiMotion.cardShift, value: isActive)
        .accessibilityHidden(true)
    }
}

struct PrimaryActionButton: View {
    @Environment(\.vdpiPalette) private var palette
    let title: String
    let isLoading: Bool
    let isDestructiveOutline: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                if isLoading {
                    ProgressView()
                        .progressViewStyle(.circular)
                        .tint(isDestructiveOutline ? palette.inkPrimary : palette.primaryButtonInk)
                        .scaleEffect(0.85)
                }
                Text(title)
                    .font(.system(size: 15, weight: .semibold))
                    .tracking(-0.2)
            }
            .frame(maxWidth: .infinity)
            .frame(minHeight: 50)
            .foregroundStyle(isDestructiveOutline ? palette.inkPrimary : palette.primaryButtonInk)
            .modifier(PrimaryButtonSurfaceModifier(isDestructiveOutline: isDestructiveOutline))
        }
        .buttonStyle(VdpiPressButtonStyle(haptic: .medium))
        .disabled(isLoading)
    }
}

private struct PrimaryButtonSurfaceModifier: ViewModifier {
    @Environment(\.vdpiPalette) private var palette
    let isDestructiveOutline: Bool

    func body(content: Content) -> some View {
        if isDestructiveOutline {
            content
                .vdpiGlass(
                    in: Capsule(),
                    tier: .elevated,
                    tint: palette.dangerTint.opacity(0.65),
                    borderAccent: palette.danger.opacity(0.45),
                    interactive: true
                )
        } else {
            content
                .background {
                    ZStack {
                        Capsule().fill(palette.primaryButtonBg)
                        Capsule()
                            .fill(
                                LinearGradient(
                                    stops: [
                                        .init(
                                            color: palette.isDark
                                                ? Color.white.opacity(0.35)
                                                : Color.white.opacity(0.22),
                                            location: 0.0
                                        ),
                                        .init(color: .clear, location: 0.55),
                                    ],
                                    startPoint: .top,
                                    endPoint: .bottom
                                )
                            )
                    }
                }
                .clipShape(Capsule())
                .overlay {
                    Capsule()
                        .strokeBorder(palette.specularRim(), lineWidth: 0.85)
                        .allowsHitTesting(false)
                }
                .shadow(color: palette.shadowColor, radius: 14, x: 0, y: 6)
        }
    }
}

struct GhostActionButton: View {
    @Environment(\.vdpiPalette) private var palette
    let title: String
    let systemImage: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Image(systemName: systemImage)
                    .font(.system(size: 13, weight: .medium))
                Text(title)
                    .font(.system(size: 13, weight: .medium))
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity)
            .frame(minHeight: 44)
            .padding(.horizontal, 12)
            .foregroundStyle(palette.inkPrimary)
            .vdpiGlass(in: Capsule(), tier: .subtle, interactive: true)
        }
        .buttonStyle(VdpiPressButtonStyle(haptic: .light))
    }
}

struct MetricTile: View {
    @Environment(\.vdpiPalette) private var palette
    let label: String
    let value: String
    let systemImage: String?

    init(label: String, value: String, systemImage: String? = nil) {
        self.label = label
        self.value = value
        self.systemImage = systemImage
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 4) {
                if let systemImage {
                    Image(systemName: systemImage)
                        .font(.system(size: 9.5, weight: .semibold))
                        .foregroundStyle(palette.inkMuted)
                }
                Text(label.uppercased())
                    .font(.system(size: 10, weight: .medium, design: .monospaced))
                    .tracking(0.7)
                    .foregroundStyle(palette.inkMuted)
                    .lineLimit(1)
            }
            Text(value)
                .font(.system(size: 15, weight: .semibold, design: .monospaced))
                .monospacedDigit()
                .foregroundStyle(palette.inkPrimary)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
                .contentTransition(.numericText())
                .animation(VdpiMotion.cardShift, value: value)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 10)
        .padding(.horizontal, 12)
        .vdpiGlass(
            in: RoundedRectangle(cornerRadius: 12, style: .continuous),
            tier: .subtle
        )
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label): \(value)")
    }
}

struct StatusPill: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    let text: String
    let tint: Color
    let background: Color
    let border: Color
    let isPulsing: Bool

    @State private var pulseActive: Bool = false

    init(
        text: String,
        tint: Color,
        background: Color,
        border: Color,
        isPulsing: Bool = false
    ) {
        self.text = text
        self.tint = tint
        self.background = background
        self.border = border
        self.isPulsing = isPulsing
    }

    var body: some View {
        HStack(spacing: 6) {
            ZStack {
                if isPulsing && !reduceMotion {
                    Circle()
                        .fill(tint.opacity(pulseActive ? 0.0 : 0.55))
                        .frame(width: 7, height: 7)
                        .scaleEffect(pulseActive ? 2.4 : 1.0)
                        .animation(
                            pulseActive
                                ? .easeOut(duration: 1.4).repeatForever(autoreverses: false)
                                : .default,
                            value: pulseActive
                        )
                }
                Circle()
                    .fill(tint)
                    .frame(width: 7, height: 7)
                    .shadow(color: tint.opacity(0.65), radius: 4, x: 0, y: 0)
            }
            .frame(width: 10, height: 10)

            Text(text)
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .foregroundStyle(tint)
                .lineLimit(1)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .vdpiGlass(
            in: Capsule(),
            tier: .subtle,
            tint: background,
            borderAccent: border
        )
        .onAppear {
            pulseActive = isPulsing && !reduceMotion
        }
        .vdpiOnChange(of: isPulsing) { pulsing in
            pulseActive = pulsing && !reduceMotion
        }
        .vdpiOnChange(of: reduceMotion) { reduced in
            pulseActive = isPulsing && !reduced
        }
    }
}
