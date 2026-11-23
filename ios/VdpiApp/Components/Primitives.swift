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

// MARK: - Floating Functional Layer (Liquid Glass)

/// Material density tier for floating chrome only (tab bar, floating live-tunnel pill,
/// top-floating reconnect banner, circular toolbar buttons, floating toasts).
/// Never apply Liquid Glass to content-layer cards, lists, or rows.
enum VdpiGlassTier: Equatable, Sendable {
    case subtle
    case regular
    case elevated
}

struct VdpiGlassSurfaceModifier<S: InsettableShape>: ViewModifier {
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorSchemeContrast) private var colorSchemeContrast

    let shape: S
    let tier: VdpiGlassTier
    let tint: Color?
    let borderAccent: Color?
    let interactive: Bool

    init(
        shape: S,
        tier: VdpiGlassTier,
        tint: Color?,
        borderAccent: Color?,
        interactive: Bool
    ) {
        self.shape = shape
        self.tier = tier
        self.tint = tint
        self.borderAccent = borderAccent
        self.interactive = interactive
    }

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
    private func makeNativeGlass() -> Glass {
        let baseGlass: Glass = .regular
        let tintedGlass: Glass = tint.map { baseGlass.tint($0) } ?? baseGlass
        return interactive ? tintedGlass.interactive() : tintedGlass
    }

    @available(iOS 26.0, *)
    private func nativeLiquidGlass(for content: Content) -> some View {
        content
            .glassEffect(makeNativeGlass(), in: shape)
            .overlay {
                if colorSchemeContrast == .increased {
                    shape
                        .strokeBorder(palette.borderStrong, lineWidth: 1.25)
                        .allowsHitTesting(false)
                } else if let borderAccent {
                    shape
                        .strokeBorder(
                            palette.specularRim(accent: borderAccent),
                            lineWidth: 0.5
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
                }
            }
            .clipShape(shape)
            .overlay {
                if colorSchemeContrast == .increased {
                    shape
                        .strokeBorder(borderAccent ?? palette.borderStrong, lineWidth: 1.0)
                        .allowsHitTesting(false)
                } else {
                    shape
                        .strokeBorder(
                            palette.specularRim(accent: borderAccent),
                            lineWidth: 0.5
                        )
                        .allowsHitTesting(false)
                }
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
                    .strokeBorder(
                        borderAccent ?? (colorSchemeContrast == .increased ? palette.borderStrong : palette.border),
                        lineWidth: colorSchemeContrast == .increased ? 1.25 : 0.75
                    )
                    .allowsHitTesting(false)
            }
    }

    private var materialForTier: Material {
        switch tier {
        case .subtle:
            return .ultraThinMaterial
        case .regular, .elevated:
            return .regularMaterial
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
            return palette.shadowColor.opacity(0.45)
        case .regular:
            return palette.shadowColor.opacity(0.75)
        case .elevated:
            return palette.shadowColor
        }
    }

    private var shadowRadiusForTier: CGFloat {
        switch tier {
        case .subtle:
            return 6
        case .regular:
            return 12
        case .elevated:
            return 18
        }
    }

    private var shadowYOffsetForTier: CGFloat {
        switch tier {
        case .subtle:
            return 2
        case .regular:
            return 4
        case .elevated:
            return 8
        }
    }
}

extension View {
    /// Applies Liquid Glass (iOS 26+) or Apple material fallback (iOS 16-18).
    /// Strictly reserved for floating functional chrome (tab bar, floating accessory pill,
    /// floating banner, circular toolbar buttons, floating toasts).
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

// MARK: - Content Layer Containers (Opaque Apple Grouped Surfaces)

/// Clean opaque Apple grouped surface container (zero blur, zero shadow, zero outer border).
struct InsetGroupedCard<Content: View>: View {
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.colorSchemeContrast) private var colorSchemeContrast

    var cornerRadius: CGFloat
    @ViewBuilder let content: () -> Content

    init(
        cornerRadius: CGFloat = 16,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.cornerRadius = cornerRadius
        self.content = content
    }

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        content()
            .background(shape.fill(palette.surface))
            .clipShape(shape)
            .overlay {
                if colorSchemeContrast == .increased {
                    shape
                        .strokeBorder(palette.borderStrong, lineWidth: 1.0)
                        .allowsHitTesting(false)
                }
            }
    }
}

/// Refined 42x42 circular floating Liquid Glass toolbar button with 44x44 minimum hit target.
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
                    .font(.body.weight(.medium))
                    .foregroundStyle(tint ?? palette.inkPrimary)
                    .rotationEffect(.degrees(spinPhase ? 360 : 0))
                    .animation(
                        reduceMotion
                            ? nil
                            : (spinPhase
                                ? .linear(duration: 1.0).repeatForever(autoreverses: false)
                                : .easeOut(duration: 0.2)),
                        value: spinPhase
                    )
                    .frame(width: 42, height: 42)
                    .vdpiGlass(
                        in: Circle(),
                        tier: .subtle,
                        tint: tint.map { $0.opacity(palette.isDark ? 0.14 : 0.10) },
                        interactive: true
                    )

                if let badgeColor {
                    Circle()
                        .fill(badgeColor)
                        .frame(width: 8, height: 8)
                        .overlay(
                            Circle()
                                .strokeBorder(palette.canvas, lineWidth: 1.5)
                        )
                        .offset(x: -1, y: 1)
                }
            }
            .frame(width: 44, height: 44)
            .contentShape(Circle())
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

// MARK: - Grouped List Chrome & Scroll Edge Scrim

/// Authentic 1-pixel (`1 / displayScale`) inset separator for Apple grouped list rows.
struct InsetDivider: View {
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.displayScale) private var displayScale

    var leadingInset: CGFloat

    init(leadingInset: CGFloat = 16) {
        self.leadingInset = leadingInset
    }

    var body: some View {
        Rectangle()
            .fill(palette.border.opacity(0.65))
            .frame(height: 1.0 / max(displayScale, 1.0))
            .padding(.leading, leadingInset)
            .accessibilityHidden(true)
    }
}

/// Authentic Apple grouped section header (`.footnote`, Dynamic Type, muted ink).
struct SectionHeader: View {
    @Environment(\.vdpiPalette) private var palette
    let title: String

    init(title: String) {
        self.title = title
    }

    init(_ title: String) {
        self.title = title
    }

    var body: some View {
        Text(title)
            .font(.footnote)
            .textCase(.uppercase)
            .foregroundStyle(palette.inkMuted)
            .padding(.horizontal, 16)
            .accessibilityAddTraits(.isHeader)
    }
}

/// Authentic Apple grouped section footer (`.footnote`, Dynamic Type, muted ink).
struct SectionFooter: View {
    @Environment(\.vdpiPalette) private var palette
    let text: String

    init(text: String) {
        self.text = text
    }

    init(_ text: String) {
        self.text = text
    }

    var body: some View {
        Text(text)
            .font(.footnote)
            .foregroundStyle(palette.inkMuted)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 16)
    }
}

/// Smooth multi-stop fade into `palette.canvas` so scrolling content dissolves softly
/// behind the floating tab bar or top floating chrome.
struct ScrollEdgeFadeScrim: View {
    @Environment(\.vdpiPalette) private var palette

    let height: CGFloat
    let fromBottom: Bool

    init(height: CGFloat = 96, fromBottom: Bool = true) {
        self.height = height
        self.fromBottom = fromBottom
    }

    var body: some View {
        LinearGradient(
            stops: [
                .init(color: palette.canvas.opacity(0.0), location: 0.0),
                .init(color: palette.canvas.opacity(0.18), location: 0.25),
                .init(color: palette.canvas.opacity(0.55), location: 0.52),
                .init(color: palette.canvas.opacity(0.88), location: 0.78),
                .init(color: palette.canvas, location: 1.0),
            ],
            startPoint: fromBottom ? .top : .bottom,
            endPoint: fromBottom ? .bottom : .top
        )
        .frame(height: height)
        .ignoresSafeArea(edges: fromBottom ? .bottom : .top)
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

// MARK: - Interactive Controls & Indicators

struct VdpiPressButtonStyle: ButtonStyle {
    var haptic: VdpiHaptics.Kind?

    init(haptic: VdpiHaptics.Kind? = .light) {
        self.haptic = haptic
    }

    func makeBody(configuration: Configuration) -> some View {
        PressBody(configuration: configuration, haptic: haptic)
    }

    private struct PressBody: View {
        @Environment(\.accessibilityReduceMotion) private var reduceMotion

        let configuration: Configuration
        let haptic: VdpiHaptics.Kind?

        var body: some View {
            configuration.label
                .scaleEffect(configuration.isPressed && !reduceMotion ? 0.97 : 1.0)
                .opacity(configuration.isPressed ? 0.86 : 1.0)
                .animation(reduceMotion ? nil : VdpiMotion.press, value: configuration.isPressed)
                .vdpiOnChange(of: configuration.isPressed) { isPressed in
                    if isPressed, let haptic {
                        Task { @MainActor in
                            VdpiHaptics.trigger(haptic)
                        }
                    }
                }
        }
    }
}

/// Apple prominent capsule action button (primary system fill or quiet tonal capsule).
struct PrimaryActionButton: View {
    @Environment(\.vdpiPalette) private var palette
    @Environment(\.colorSchemeContrast) private var colorSchemeContrast

    let title: String
    let isLoading: Bool
    let isDestructiveOutline: Bool
    let action: () -> Void

    init(
        title: String,
        isLoading: Bool = false,
        isDestructiveOutline: Bool = false,
        action: @escaping () -> Void
    ) {
        self.title = title
        self.isLoading = isLoading
        self.isDestructiveOutline = isDestructiveOutline
        self.action = action
    }

    var body: some View {
        let foreground = isDestructiveOutline ? palette.inkPrimary : palette.primaryButtonInk
        let background = isDestructiveOutline ? palette.surfaceRaised : palette.primaryButtonBg

        Button(action: action) {
            HStack(spacing: 8) {
                if isLoading {
                    ProgressView()
                        .progressViewStyle(.circular)
                        .tint(foreground)
                        .scaleEffect(0.85)
                }
                Text(title)
                    .font(.headline)
            }
            .frame(maxWidth: .infinity)
            .frame(minHeight: 50)
            .padding(.horizontal, 16)
            .foregroundStyle(foreground)
            .background(Capsule().fill(background))
            .clipShape(Capsule())
            .overlay {
                if colorSchemeContrast == .increased {
                    Capsule()
                        .strokeBorder(palette.borderStrong, lineWidth: 1.0)
                        .allowsHitTesting(false)
                }
            }
            .contentShape(Capsule())
        }
        .buttonStyle(VdpiPressButtonStyle(haptic: nil))
        .disabled(isLoading)
    }
}
