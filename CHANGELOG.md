# Changelog

All notable changes to `vdpi` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-11-24

### Added

- `ratatui` console launcher and live foreground dashboard with 60s throughput sparkline, scrollable event log, diagnostics overlay, and version-aware 1-press updater.
- `vdpi update` SHA-256-verified self-updater on desktop and quiet GitHub Releases update checker on Android and iOS.
- Persistent adaptive DPI stage cache across Windows, macOS, Linux, Android, and iOS.
- Android and iOS UI additions: Activity-Monitor throughput sparkline, numeric ticker transitions, dark-mode specular card hairlines, settings JSON backup/restore, and 1-tap shareable diagnostics reports.
- Android minimal Home Screen toggle widget and iOS Siri Shortcuts / Automations via `AppIntents`.

### Changed

- Reorganized monorepo into colocated `core/`, `android/`, and `ios/` directories.

## [0.3.4] - 2026-11-23

### Added

- Apple Liquid Glass navigation bar, adaptive landscape layouts, and GitHub attribution across Android and iOS.

### Fixed

- Qualified `Network.NWPath` in iOS `PacketTunnelProvider` to resolve `NetworkExtension` type ambiguity.
- Restored desktop `launcher.rs` after CRLF normalization truncation.
- Resolved mobile UI and runtime QA issues.

## [0.3.3] - 2026-11-23

### Changed

- Apple HIG mobile UI overhaul with Split-Packet DPI app icon and WCAG AA contrast improvements across Android and iOS.

## [0.3.2] - 2026-11-23

### Added

- Mobile Liquid Glass UI redesign, cross-tab "Settings Changed" reconnect prompt, and top-pinned Android VPN status notification.
- Unsigned `vdpi-ios-unsigned.ipa` release packaging with ad-hoc `arm64` entitlements via `ldid-procursus`.

### Fixed

- Configured `CODE_SIGN_ENTITLEMENTS` in iOS `project.yml` so XcodeGen preserves `.entitlements` files.
- Fixed release workflow entitlement verification and restricted automatic release runs to version tags and manual dispatch.

[0.4.0]: https://github.com/Vuln-Inc/vdpi/compare/v0.3.4...v0.4.0
[0.3.4]: https://github.com/Vuln-Inc/vdpi/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/Vuln-Inc/vdpi/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/Vuln-Inc/vdpi/compare/v0.3.1...v0.3.2
