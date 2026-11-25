# Changelog

All notable changes to `vdpi` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.2] - 2026-11-25

### Fixed

- macOS TUN `ERR_NAME_NOT_RESOLVED`: replaced `networksetup -setdnsservers` (which scoped `198.18.0.2` onto physical `en0` and broke `mDNSResponder`) with native `SCDynamicStore` session keys bound to `utunN` (`State:/Network/Service/com.vdpi.tun/*`, automatically cleaned by `configd` on exit or crash), added explicit `-ifscope` default routes plus 8 non-zero-anchor split routes (`1.0.0.0/8`..`128.0.0.0/1`) so `IP_BOUND_IF` never hits `ENETUNREACH`, fixed `/sbin/route add` exit-0 `"File exists"` handling and `link#` gateway rejection, wired `route_rx` into macOS TUN pipeline, and added automatic startup cleanup for any stale v0.5.x `198.18.0.2` Wi-Fi DNS entry.
- Desktop TUN Gigabit throughput & low latency across Windows, macOS, and Linux: replaced `netstack-smoltcp` with an in-tree `smoltcp` 0.14 TCP runner (`ack_delay = None`, `nagle = false`, `Checksum::Tx`, poll-to-quiescence, zero silent TCP drops), raised desktop TUN MTU to `16384` (with `9000`/`1500` fallback on macOS and RFC 9715 1232-byte DNS cap), upgraded desktop TCP buffers to `512 KiB` (activating RFC 7323 window scaling), raised Wintun rings to 16 MiB/direction with batched RX/TX and 1ms Windows timer resolution, raised desktop relay buffers to `128 KiB`, and bumped Linux TUN `txqueuelen` to `4096`.
- Windows service TUN mode now passes `route_rx` into the TUN pipeline so uplink switches immediately drain and rebind UDP Cone-NAT flows, and statically links the MSVC CRT (`+crt-static`) in release builds so `vdpi.exe` runs with zero `VCRUNTIME140.dll` dependency on clean Windows machines and WinGet validation VMs.
- Linux TUN & `systemd` reliability: guarded `--internal-linux-tun-cleanup` (`ExecStopPost`) with non-blocking `flock` on `/run/vdpi/tun.lock`, fixed non-stub `/run/systemd/resolve/resolv.conf` detection and `nmcli general reload`, removed `CapabilityBoundingSet=CAP_NET_ADMIN` from the root `systemd` unit, ordered `After=systemd-resolved.service NetworkManager.service`, and added fast-fail detection for non-root Linux TUN errors.
- Bound DoH & UDP DNS hardening: skipped HTTP/2-only Quad9 endpoints in HTTP/1.1 bound DoH, added `Content-Length` fast-return and chunked decoding, appended RFC 2308 Authority SOA records on negative/NODATA replies, widened raw UDP DNS buffers to 4096 bytes with stray-packet skipping, and expanded raw UDP failover across all configured servers.

### Docs

- Documented Proxy (default) vs TUN engine modes and switching workflows in `README.md`, and fixed relative links for crates.io rendering.

## [0.5.1] - 2026-11-25

### Fixed

- macOS and Linux interactive `sudo` elevation prompt when switching between Proxy and TUN mode, installing/pausing/resuming/uninstalling a root TUN service, or starting foreground TUN from the Control Center TUI (matching Windows UAC elevation).
- Windows foreground TUN start from Control Center now prompts for UAC elevation when not running as Administrator.
- macOS `LaunchDaemon` engine switch and resume no longer `kickstart -k` immediately after `bootstrap` (`RunAtLoad=true`), always updates `/usr/local/bin/vdpi` to the current binary, and waits up to 2.5s for TUN `/vdpi-health` readiness.
- `load_configured_engine()` now prefers system `config.toml` when a TUN system daemon or Windows service is installed so paused TUN services display the correct engine mode in Control Center and `vdpi status`.

## [0.5.0] - 2026-11-25

### Added

- Desktop Transparent TUN Mode across Windows (Wintun), macOS (`utun`), and Linux (`/dev/net/tun`) for system-wide DPI bypass without per-app proxy configuration.
- `VpnGuard` desktop VPN coexistence with 0ms yield when a third-party VPN connects and 3s automatic recovery after the VPN disconnects.
- Persistent `config.toml` configuration along with `vdpi engine` and `vdpi config` CLI subcommands.
- Control Center v2 and Foreground Dashboard v2 with engine mode switching, live TUN/Proxy status telemetry, and updated diagnostics.
- Pinned Wintun `0.14.1` packaging in `vdpi-windows-x86_64.zip` (`wintun.dll` and `WINTUN-LICENSE.txt` beside `vdpi.exe`) verified by archive SHA-256, DLL SHA-256, and `WireGuard LLC` Authenticode signature in CI.
- Automated `cargo tree` mobile and cross-OS crate isolation gate in release CI verifying `vdpi-android` and `vdpi-ios` never pull `vdpi`, `ratatui`, `crossterm`, `clap`, or `windows-sys`.

### Changed

- Preserved Desktop Proxy Mode continuity with zero-disruption `vdpi update` in-place upgrades.
- Split the workspace into acyclic `vdpi-core` and `vdpi-tun` crates shared across desktop, Android, and iOS.
- Streamlined `README.md` and reorganized platform and architecture guides into `docs/`.

### Fixed

- Added zero-lag UDP fast-path with Windows `SIO_UDP_CONNRESET` handling and clean ICMP-backed QUIC fallback.
- Improved `isp_stage` promotion hygiene so isolated host anomalies no longer over-promote global ISP desync stages.

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

[Unreleased]: https://github.com/Vuln-Inc/vdpi/compare/v0.5.2...HEAD
[0.5.2]: https://github.com/Vuln-Inc/vdpi/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/Vuln-Inc/vdpi/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/Vuln-Inc/vdpi/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/Vuln-Inc/vdpi/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/Vuln-Inc/vdpi/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/Vuln-Inc/vdpi/compare/v0.3.4...v0.4.0
[0.3.4]: https://github.com/Vuln-Inc/vdpi/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/Vuln-Inc/vdpi/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/Vuln-Inc/vdpi/compare/v0.3.1...v0.3.2
