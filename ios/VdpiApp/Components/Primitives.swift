import SwiftUI

struct HairlinePanel<Content: View>: View {
    @Environment(\.vdpiPalette) private var palette
    var borderColor: Color? = nil
    var backgroundColor: Color? = nil
    var cornerRadius: CGFloat = 14
    @ViewBuilder let content: () -> Content

    var body: some View {
        content()
            .background(backgroundColor ?? palette.surface)
            .clipShape(RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .strokeBorder(borderColor ?? palette.border, lineWidth: 1)
            )
    }
}

struct HairlineRule: View {
    @Environment(\.vdpiPalette) private var palette

    var body: some View {
        Rectangle()
            .fill(palette.border)
            .frame(height: 1)
    }
}

struct VdpiPressButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.985 : 1.0)
            .opacity(configuration.isPressed ? 0.88 : 1.0)
            .animation(.spring(response: 0.22, dampingFraction: 0.78), value: configuration.isPressed)
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

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(palette.surfaceRaised)
                .overlay(
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .strokeBorder(palette.borderStrong, lineWidth: 1)
                )
                .frame(width: 30, height: 30)

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
                    with: .color(palette.signal),
                    style: StrokeStyle(lineWidth: 2.3, lineCap: .round)
                )
            }
            .frame(width: 22, height: 22)
        }
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
            .background(isDestructiveOutline ? palette.surfaceRaised : palette.primaryButtonBg)
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .strokeBorder(
                        isDestructiveOutline ? palette.borderStrong : Color.clear,
                        lineWidth: 1
                    )
            )
        }
        .buttonStyle(VdpiPressButtonStyle())
        .disabled(isLoading)
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
            .background(palette.surface)
            .clipShape(RoundedRectangle(cornerRadius: 11, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 11, style: .continuous)
                    .strokeBorder(palette.border, lineWidth: 1)
            )
        }
        .buttonStyle(VdpiPressButtonStyle())
    }
}

struct MetricTile: View {
    @Environment(\.vdpiPalette) private var palette
    let label: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label.uppercased())
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .tracking(0.7)
                .foregroundStyle(palette.inkMuted)
                .lineLimit(1)
            Text(value)
                .font(.system(size: 15, weight: .semibold, design: .monospaced))
                .monospacedDigit()
                .foregroundStyle(palette.inkPrimary)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 10)
        .padding(.horizontal, 12)
        .background(palette.surfaceRaised.opacity(palette.isDark ? 0.65 : 0.7))
        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(palette.border, lineWidth: 1)
        )
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label): \(value)")
    }
}

struct StatusPill: View {
    let text: String
    let tint: Color
    let background: Color
    let border: Color

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(tint)
                .frame(width: 7, height: 7)
            Text(text)
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .foregroundStyle(tint)
                .lineLimit(1)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(background)
        .clipShape(Capsule())
        .overlay(Capsule().strokeBorder(border, lineWidth: 1))
    }
}
