# Changelog

All notable changes to `vdpi` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.2] - 2026-11-24

### Added

- Interactive `ratatui` Control Center showing live Service state and Anti-DPI engine telemetry (desync mode, DoH, QUIC blocking, active connections, cached hosts) with `r` live refresh.
- Temporary background service pause and resume (`vdpi pause` / `vdpi stop`, `vdpi resume`, and 1-press toggle inside the TUI) without uninstalling files or service registration.
- Interactive `Uninstall vdpi` with inline confirmation and `Run diagnostics` directly from the Control Center TUI.

### Changed

- Enriched local `/vdpi-health` telemetry JSON with live Anti-DPI engine metrics and upgraded `vdpi status` output.

## [0.4.1] - 2026-11-24

### Added

- Dynamic iOS App Group and PacketTunnel extension bundle ID auto-detection (`embedded.mobileprovision` + `PlugIns/*.appex/Info.plist`) so paid Apple Developer / Sideloadly / Feather re-signing connects without manual Swift edits.
- One-line SHA-256-verified desktop install scripts (`install.sh` for macOS/Linux and `install.ps1` for Windows) hosted on GitHub Pages alongside direct Scoop (`vdpi.json`) and AltStore/SideStore/Feather (`apps.json`) feeds.

### Changed

- Android release APKs are now signed with the persistent repository release keystore (`VDPI_KEYSTORE_BASE64`) for seamless in-place upgrades via GitHub Releases and Obtainium.

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

[Unreleased]: https://github.com/Vuln-Inc/vdpi/compare/v0.4.2...HEAD
[0.4.2]: https://github.com/Vuln-Inc/vdpi/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/Vuln-Inc/vdpi/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/Vuln-Inc/vdpi/compare/v0.3.4...v0.4.0
[0.3.4]: https://github.com/Vuln-Inc/vdpi/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/Vuln-Inc/vdpi/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/Vuln-Inc/vdpi/compare/v0.3.1...v0.3.2
