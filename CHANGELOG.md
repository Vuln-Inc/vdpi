# Changelog

All notable changes to `vdpi` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-11-27

### Added
- **Native cross-platform Desktop GUI (`vdpi Desktop`) for Windows, macOS, and Linux**:
  - Built with Tauri v2 + React 19 with a clean Light/Dark/System aesthetic (no neon glows or clutter), Overview live status & throughput chart, visual Split Tunneling with search, one-click app/game presets, companion process inspection, and custom app picker, DNS & Rules editor with custom DoH token redaction, built-in read-only Diagnostics with redacted report copy, and Settings.
  - Optional system tray / menu bar behavior (`Keep in system tray when closed`, `Minimize to tray`, `Start minimized to tray`, and `Show taskbar/Dock icon when minimized`) — stays out of the tray/taskbar completely when disabled.
  - Bundled `vdpi` CLI sidecar with OS-native privilege prompts (`ShellExecuteExW` UAC on Windows, `osascript` on macOS, `pkexec` with AppImage FUSE staging on Linux) and argv-free owner-only atomic config handoff (`vdpi config apply-file`).
  - Added Desktop release artifacts for Windows (NSIS installer & portable zip with loose WHQL-signed `wintun.dll`), macOS universal `.dmg` (`arm64` + `x86_64`), and Linux `.deb` + `.AppImage`.

### Changed
- **Hardened core engine, service control, split tunneling, and mobile apps**:
  - Added wildcard (`*.example.org`, `.example.org`) and anchored plain-domain translation for `include_domains` while preserving raw regex compatibility.
  - Hardened service installation, config persistence, DNS/DoH redaction, Windows `ProgramData` ACLs & symlink/reparse checks, macOS LaunchDaemon/pf & Linux systemd/ostree/Wayland compatibility, and Android/iOS TUN parity.
  - Guarded Windows console pause prompts so hidden elevated sidecar runs never stall waiting for input.

## [0.5.8] - 2026-11-27

### Added
- **Fail-open PAC system proxy on Windows & macOS**:
  - Served a local PAC script at `GET /vdpi.pac` returning `PROXY 127.0.0.1:<port>; DIRECT` and configured OS proxy integration via Windows `AutoConfigURL` and macOS `AutoProxyURL` so terminating, crashing, or quarantining `vdpi` automatically falls back to `DIRECT` and can never leave a user's internet broken.
- **Windows PE `VS_VERSION_INFO` metadata & loose `wintun.dll` packaging**:
  - Embedded Windows PE `VS_VERSION_INFO` metadata (`ProductName`, `CompanyName`, `FileDescription`, `ProductVersion`) directly into `vdpi.exe`.
  - Packaged the unmodified WHQL-signed `wintun.dll` and `WINTUN-LICENSE.txt` as loose sidecar files inside `vdpi-windows-x86_64.zip` instead of embedding a binary blob inside `vdpi.exe`, minimizing antivirus false positives.

## [0.5.7] - 2026-11-27

### Added
- **Standalone Windows `vdpi.exe` with embedded WHQL-signed Wintun**:
  - Release CI now downloads and verifies Wintun `0.14.1` (archive SHA-256, DLL SHA-256, and `WireGuard LLC` Authenticode signature) prior to compilation and embeds it directly inside `vdpi.exe` via `VDPI_EMBED_WINTUN_DLL`, shipping a single standalone `vdpi.exe` inside `vdpi-windows-x86_64.zip` with no loose `wintun.dll` sidecar.
- **Interactive TUI `[7] Custom DNS` IP & DoH picker**:
  - Added `[7] Custom DNS` input in the Control Center DNS server selector and unified CLI (`vdpi dns`) + TUI validation via `vdpi_core::dns::validate_custom_dns_input`, accepting preset names as well as any valid IPv4, IPv6, or `https://` DoH URL.
  - Added compact formatting and truncation for long custom DoH URLs in the live TUI dashboard so panel borders stay intact down to `46x18`.

### Fixed
- **Gigabit TUN + zero-audio-stutter overhaul**:
  - Capped foreground Tokio runtime worker threads (`2..=4`) so high-throughput desktop TUN traffic never preempts real-time audio engines such as VoiceMeeter.
  - Updated Windows missing-`wintun.dll` hints to note embedded Wintun in official release builds.

## [0.5.6] - 2026-11-26

### Added
- **Interactive TUI screens for Software Update and Network Diagnostics**:
  - Added full `ratatui` TUI views for **Software Update** (live GitHub release check spinner, word-wrapped release notes, one-key update) and **Network Diagnostics** (live per-check progress and latency).

### Changed
- **Persistent Control Center workflow**:
  - Control Center now stays open with live status notices after Update, Diagnostics, Install, and Uninstall instead of abruptly closing the terminal.
- **Seamless automatic elevation & clean approval prompt**:
  - Added automatic `sudo` (macOS/Linux) and UAC (Windows) elevation across Update, LaunchDaemon/systemd upgrade, Split Tunneling save, `vdpi config`, and foreground TUN start, eliminating raw permission and LaunchDaemon errors.
  - Added a clean rounded-card administrator approval prompt for `sudo` with proper alignment and clean screen transitions.

## [0.5.5] - 2026-11-26

### Added
- **Live dashboard attach for running background service**:
  - Added Control Center `[1] Open live dashboard` (hotkey `l`) to attach in real time to the running background TUN or Proxy service without restarting it.
  - Added `vdpi dashboard` (alias `dash`) CLI command for direct live dashboard attach.
  - Displays live RX/TX throughput sparkline, active/total connections, DoH queries, TLS/auto-heal telemetry, ISP stage, process RSS, inline diagnostics (`d`), and automatic reconnect on service restart.
- **Desktop Per-App Split Tunneling**:
  - Added cross-platform per-app split tunneling across Windows (`GetExtendedTcpTable`/`GetExtendedUdpTable`), macOS (`lsof` + `.app` bundle discovery), and Linux (pure `/proc` + `.desktop` discovery) in both TUN and Proxy modes.
  - Added interactive TUI Split-Tunneling App Picker (`s` in Control Center or `vdpi split` / `vdpi apps`) with live instant fuzzy search (`/`), All / Include / Exclude mode switcher (`Tab`), running-app indicators, and custom executable entry (`a`).
  - Added persistent `split_tunnel_mode` and `split_tunnel_apps` in `config.toml`, CLI flags (`--split-mode`, `--split-app`), and `vdpi split` subcommands.

## [0.5.4] - 2026-11-25

### Added
- **Desktop TUI DNS server picker & `vdpi dns` CLI command (`core/src/launcher.rs`, `core/src/launcher/tui.rs`, `core/src/service.rs`, `core/src/config.rs`, `core/src/main.rs`)**:
  - Added an inline DNS server selector in the interactive Control Center TUI (`Choose DNS server` menu entry and `d` hotkey) with built-in DoH presets: Cloudflare (`1.1.1.1`), Google (`8.8.8.8`), AdGuard (`94.140.14.14`), AdGuard Unfiltered (`94.140.14.140`), Quad9 (`9.9.9.9`), and Cloudflare Family (`1.1.1.3`), plus `[Active]` indicator and fallback non-TUI console selection.
  - Added `vdpi dns [SERVER]` CLI command and `set_service_dns` persistence/restart support across Windows, macOS, and Linux (auto-elevates cleanly when updating an installed system service and restarts the running service immediately).

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

[Unreleased]: https://github.com/Vuln-Inc/vdpi/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/Vuln-Inc/vdpi/compare/v0.5.8...v0.6.0
[0.5.8]: https://github.com/Vuln-Inc/vdpi/compare/v0.5.7...v0.5.8
[0.5.7]: https://github.com/Vuln-Inc/vdpi/compare/v0.5.6...v0.5.7
[0.5.6]: https://github.com/Vuln-Inc/vdpi/compare/v0.5.5...v0.5.6
[0.5.5]: https://github.com/Vuln-Inc/vdpi/compare/v0.5.4...v0.5.5
[0.5.4]: https://github.com/Vuln-Inc/vdpi/compare/v0.5.3...v0.5.4
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
