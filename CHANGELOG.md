# Changelog

All notable changes to `vdpi` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.3] - 2026-11-25

### Fixed
- **iOS / TUN TCP netstack `SynReceived` + `RST` -> `Listen` deadlock & session starvation (`core/tun/src/netstack.rs`, `core/tun/src/config.rs`)**:
  - Tracked `saw_non_listen` so `smoltcp` 0.14 sockets reverted from `SynReceived` back to `Listen` on client `RST` are aborted immediately instead of poisoning `listening_dsts` for 30s and wedging subsequent SYNs.
  - Replaced the single `pending_frame` halt with a bounded `deferred_syns` queue + 3s orphan `Listen` reaper so `tcp_in_rx` never stops draining ACKs, FINs, RSTs, or other destinations.
  - Counted only active non-closing sockets (`Listen`, `SynReceived`, `Established`) against `max_tcp_sessions`, added fast `TimeWait` (2s) & closing-state (5s) reapers with oldest-reclaimable eviction at `2 * max_tcp_sessions`, emitted RFC-valid IPv4/IPv6 TCP `RST+ACK` on hard capacity overflow, removed the `VirtualDevice::receive()` ACK gate, and doubled `LOW_MEMORY` `max_tcp_sessions` from `64` -> `128` (48 UDP flows, safely under iOS 256 `RLIMIT_NOFILE`).
- **iOS `utun` direct-FD congestion & proc-UUID TX framing (`core/tun/src/fd.rs`)**:
  - Matched TX `writev` prefix length (`4B` or `20B`) to `UTUN_FLAGS_ENABLE_PROC_UUID`, added bounded `ENOSPC`/`ENOBUFS` backoff retries instead of silent drops/mbuf leaks on XNU Skywalk `utun`, added transient `ENOBUFS` read recovery, and added cooperative yields on full I/O batches.
- **TUN pipeline L3 demux isolation (`core/tun/src/pipeline.rs`)**:
  - Switched `tun_to_stack` TCP forwarding to non-blocking `try_send`, moved UDP Cone-NAT slow paths off the demux loop onto bounded spawned tasks, bounded UDP/53 DNS queries to 5s, bypassed `tcp_slots` for TCP/53 DNS fallback, and bounded normal `tcp_slots` acquisition to 250ms.
- **TLS 1.3 HRR, 0-RTT, Akamai `MSG_OOB`, idle keep-alives & DoH hardening (`core/engine/src/desync.rs`, `core/engine/src/dns.rs`)**:
  - Reordered `ALL_STAGES` so clean non-OOB strategies (`Primary`, `FineFragment`, `DeepRecordStorm`, `SlowSniSlice`) precede `OobSniDesync`/`MultiRecordOob` (eliminating Akamai 2s `MSG_OOB` blackholes on `tr.rbxcdn.com`/`fts.rbxcdn.com`), normalized promotion votes by parent domain, and added sibling-CDN `*.<parent>` cache hint sharing.
  - Detected TLS 1.3 `HelloRetryRequest` and applied desync to ClientHello #2; avoided deadlocking on split/incomplete coalesced 0-RTT records; added idle-aware bidirectional relay timeout (`120s` mobile / `300s` desktop).
  - Treated sinkholed DoH responses (`0.0.0.0`/`127.0.0.1`) as DNS protocol errors instead of transport outages, required 3 consecutive full-ring DoH failures for a short 5s backoff (never 30s on one ad domain), and added HTTP/2 + TCP keepalives with `reqwest::Client` pool reset on route change.
- **iOS Sideloadly live-reload, kqueue ordering, Personal Hotspot IPv6 & MTU migration (`ios/`)**:
  - Passed settings JSON in `ProviderMessage.reloadEngineWithSettings` so live setting changes apply cleanly even without App Group sharing (fixing the infinite Reconnect banner loop).
  - Stopped previous native tunnel before registering the new `utun` fd or loading `adaptive-cache.json`, required 2 consecutive unhealthy telemetry samples before locking UI into `.error`, fixed Personal Hotspot Wi-Fi (`isExpensive == true`) IPv6 interface selection, excluded volatile IPv6 privacy addresses from path signatures, and migrated legacy `mtu = 1400` saved settings to `4064`.

## [0.5.2] - 2026-11-25

### Fixed

- macOS TUN `ERR_NAME_NOT_RESOLVED`: replaced `networksetup -setdnsservers` (which scoped `198.18.0.2` onto physical `en0` and broke `mDNSResponder`) with native `SCDynamicStore` session keys bound to `utunN` (`State:/Network/Service/com.vdpi.tun/*`, automatically cleaned by `configd` on exit or crash), added explicit `-ifscope` default routes plus 8 non-zero-anchor split routes (`1.0.0.0/8`..`128.0.0.0/1`) so `IP_BOUND_IF` never hits `ENETUNREACH`, fixed `/sbin/route add` exit-0 `"File exists"` handling and `link#` gateway rejection, wired `route_rx` into macOS TUN pipeline, and added automatic startup cleanup for any stale v0.5.x `198.18.0.2` Wi-Fi DNS entry.
- Desktop TUN Gigabit throughput & low latency across Windows, macOS, and Linux: replaced `netstack-smoltcp` with an in-tree `smoltcp` 0.14 TCP runner (`ack_delay = None`, `nagle = false`, `Checksum::Tx`, poll-to-quiescence, zero silent TCP drops), raised desktop TUN MTU to `16384` (with `9000`/`1500` fallback on macOS and RFC 9715 1232-byte DNS cap), upgraded desktop TCP buffers to `512 KiB` (activating RFC 7323 window scaling), raised Wintun rings to 16 MiB/direction with batched RX/TX and 1ms Windows timer resolution, raised desktop relay buffers to `128 KiB`, and bumped Linux TUN `txqueuelen` to `4096`.
- Windows service TUN mode now passes `route_rx` into the TUN pipeline so uplink switches immediately drain and rebind UDP Cone-NAT flows, and statically links the MSVC CRT (`+crt-static`) in release builds so `vdpi.exe` runs with zero `VCRUNTIME140.dll` dependency on clean Windows machines and WinGet validation VMs.
- Linux TUN & `systemd` reliability: guarded `--internal-linux-tun-cleanup` (`ExecStopPost`) with non-blocking `flock` on `/run/vdpi/tun.lock`, fixed non-stub `/run/systemd/resolve/resolv.conf` detection and `nmcli general reload`, removed `CapabilityBoundingSet=CAP_NET_ADMIN` from the root `systemd` unit, ordered `After=systemd-resolved.service NetworkManager.service`, and added fast-fail detection for non-root Linux TUN errors.
- Bound DoH & UDP DNS hardening: skipped HTTP/2-only Quad9 endpoints in HTTP/1.1 bound DoH, added `Content-Length` fast-return and chunked decoding, appended RFC 2308 Authority SOA records on negative/NODATA replies, widened raw UDP DNS buffers to 4096 bytes with stray-packet skipping, expanded raw UDP failover across all configured servers, capped DoH failover concurrency to 2 (preventing iOS 256-FD `EMFILE`), added IPv6 DoH fallbacks, and guaranteed `DirectPassthrough` + coalesced TLS 1.3 0-RTT auto-heal.
- iOS `NEPacketTunnelProvider` overhaul: added direct `dup(utun_fd)` -> Rust `AsyncFd` I/O (with Apple `target_vendor` PI & iOS 26 20-byte proc-UUID framing) plus a dedicated-thread batched `packetFlow` fallback (`4064` MTU), fixed false IPv6 detection on IPv4-only Wi-Fi (`pdp_ip*`/`ipsec*`) and `fc00::/7` IPv6 DNS self-exclusion, added `excludeLocalNetworks = true` / `excludeAPNs` / `excludeCellularServices` / CGNAT `100.64.0.0/10` (fixing LAN & XMEye/home cameras), enabled `LOW_MEMORY` QUIC ICMP Port Unreachable + 32 KiB/64-session Jetsam-safe limits, fixed `netstack` 256-SYN Jetsam bomb / infinite `FIN_WAIT_2` permit leak / parallel-SYN cross-wiring, added Sideloadly-proof `providerConfiguration` + `options` config delivery & wildcard App Group filtering, wired `defaultPath` KVO + `notifyRouteChange` (without wiping `adaptive-cache.json`), and surfaced startup/disconnect errors via `fetchLastDisconnectError`.

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

[Unreleased]: https://github.com/Vuln-Inc/vdpi/compare/v0.5.3...HEAD
[0.5.3]: https://github.com/Vuln-Inc/vdpi/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/Vuln-Inc/vdpi/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/Vuln-Inc/vdpi/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/Vuln-Inc/vdpi/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/Vuln-Inc/vdpi/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/Vuln-Inc/vdpi/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/Vuln-Inc/vdpi/compare/v0.3.4...v0.4.0
[0.3.4]: https://github.com/Vuln-Inc/vdpi/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/Vuln-Inc/vdpi/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/Vuln-Inc/vdpi/compare/v0.3.1...v0.3.2
