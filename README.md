<div align="center">

# `vdpi`

**Self-healing anti-DPI engine in pure Rust for Desktop, Android, and iOS.**

[![Release](https://img.shields.io/github/v/release/Vuln-Inc/vdpi?style=for-the-badge&logo=github&color=38bdf8)](https://github.com/Vuln-Inc/vdpi/releases/latest)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20Android%20%7C%20iOS-818cf8?style=for-the-badge)](#platforms)
[![Rust](https://img.shields.io/badge/Rust-2021%20Edition-c084fc?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-34d399?style=for-the-badge)](./LICENSE)

Single self-contained binary on desktop. Zero-root local VPN apps on Android and iOS. Zero kernel drivers.  
Works across ISPs and mobile networks worldwide with instant startup, zero ping penalty, and full **Discord** & **Roblox** support.

[Platforms](#platforms) · [Android App](#android-app) · [iOS App](#ios-app) · [Desktop Installation](#desktop-installation) · [How It Works](#how-it-works) · [Diagnostics](#diagnostics) · [CLI Reference](#cli-reference) · [Building from Source](#building-from-source)

</div>

---

## Platforms

Download the latest build for your device from **[GitHub Releases](https://github.com/Vuln-Inc/vdpi/releases/latest)** (all assets verified in `SHA256SUMS.txt`):

| Platform | Release Asset | Architecture / Requirements | Mode |
| :--- | :--- | :--- | :--- |
| **Android** | [`vdpi-android-universal.apk`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-android-universal.apk) | Android 8.0+ (API 26), `arm64-v8a` / `armeabi-v7a` / `x86_64` | Zero-root local `VpnService` + Rust userspace TUN |
| **Windows** | [`vdpi-windows-x86_64.zip`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-windows-x86_64.zip) | Windows 10 & 11 (`x86_64`) | Native Windows Service + WinINET + `HTTP_PROXY`/`HTTPS_PROXY` + WinHTTP |
| **macOS** | [`vdpi-macos-universal.tar.gz`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-macos-universal.tar.gz) | Apple Silicon & Intel (Universal) | `LaunchAgent` + `networksetup` proxy |
| **Linux** | [`vdpi-linux-x86_64.tar.gz`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-linux-x86_64.tar.gz) / [`vdpi-linux-arm64.tar.gz`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-linux-arm64.tar.gz) | `x86_64` & `arm64` (static `musl`) | `systemd --user` + GNOME / KDE proxy |
| **iOS / iPadOS** | Build from source (`ios/`); CI publishes `ios-xcframework` artifact (no `.ipa` in Releases) | iOS / iPadOS 16+ (`arm64`) | `NEPacketTunnelProvider` + shared Rust TUN (`VdpiCore.xcframework`) |

> **VPN coexistence note:** On desktop, `vdpi` runs as a pure userspace proxy (`127.0.0.1:8080` / `:1080`) with no kernel drivers, so it coexists alongside WireGuard, Cloudflare WARP, OpenVPN, Mullvad, and ProtonVPN. On **Android** (`VpnService`) and **iOS** (`NEPacketTunnelProvider`), `vdpi` uses the OS's zero-root local VPN API, which occupies the device's single active Personal VPN slot.

---

## Android App

`vdpi` for Android runs the exact same Rust 7-stage TLS desync engine and anti-poisoning DoH ring inside an on-device userspace TUN stack (`crates/vdpi-tun` + `crates/vdpi-android` + `netstack-smoltcp`) — no root access, no remote VPN servers, and no external traffic relay.

### Android Capabilities

- **Zero-Root Local TUN Engine:** Captures device traffic locally via `VpnService` (`198.18.0.2/30`, MTU `1400`, DNS `198.18.0.1`), desynchronizes TLS `ClientHello` handshakes in userspace, and relays UDP via a Cone-NAT table for voice and gaming traffic.
- **Anti-Poisoning DNS, Automatic IPv6 Detection & Clean QUIC Fallback:** Intercepts both UDP/53 and RFC 1035 TCP/53 DNS queries through `vdpi`'s multi-provider RFC 8484 DoH ring, automatically detects whether the underlying Wi-Fi/Cellular interface actually has global unicast IPv6 (`2000::/3`) so IPv4-only networks never blackhole dual-stack sites, and drops all UDP/443 QUIC datagrams (including RFC 9287 greased and short-header frames) for desync-eligible hosts so Chrome and webviews fall back cleanly to HTTP/2 over desynchronized TCP/TLS instead of throwing `ERR_QUIC_PROTOCOL_ERROR`.
- **Per-App Split Tunneling:** Choose between **Bypass selected** or **Only selected** apps (without requiring `QUERY_ALL_PACKAGES`).
- **Always-On VPN & Quick Settings Tile:** Supports Android's Always-On VPN setting and a live Quick Settings tile (note: do not enable *"Block connections without VPN"* lockdown mode if your device relies on bypass exclusions).
- **Live Telemetry & In-App Diagnostics:** Real-time 1 Hz counters (active TLS stage, connections, TX/RX bytes, DNS queries, blocked QUIC, active UDP flows), built-in `rustls` TLS 1.3/1.2 connectivity probes, and copyable chronological engine logs.
- **Modern Native UI:** Jetpack Compose interface with Dark, Light, and System themes, 16 KB page-aligned native libraries, WCAG AA contrast, and explicit backup exclusion rules.

### Installing on Android

1. Download **[`vdpi-android-universal.apk`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-android-universal.apk)** on your phone and install it (allow installing from your browser/file manager if prompted).
2. Open **vdpi**, tap **Connect**, and accept the Android VPN connection prompt.
3. Tap **Diagnostics** to verify live DoH resolution and TLS bypass checks against your network.

<details>
<summary>Android notes (Private DNS, battery optimization &amp; APK signing)</summary>

- **Private DNS:** If Android's system Private DNS is set to a custom hostname that your ISP blocks, switch Private DNS to *Automatic* or *Off* while using `vdpi` so DNS goes through `vdpi`'s built-in RFC 8484 DoH ring.
- **Battery optimization:** Some OEMs (Xiaomi/MIUI/HyperOS, Samsung, Oppo, Huawei) aggressively kill background VPN services. Set **vdpi** to *Unrestricted* / *No restrictions* in battery settings if the tunnel stops when the screen turns off.
- **APK signing:** Release APKs built in CI without repository signing secrets (`VDPI_KEYSTORE_BASE64`, `VDPI_KEYSTORE_PASSWORD`, `VDPI_KEY_ALIAS`, `VDPI_KEY_PASSWORD`) are signed with an ephemeral debug keystore. If a future release switches to a persistent release keystore, uninstall the older APK before installing the new one.

</details>

---

## iOS / iPadOS App

`vdpi` for iOS and iPadOS pairs a native SwiftUI app (`VdpiApp`) with a Network Extension (`VdpiPacketTunnel`) powered by the exact same shared Rust TUN engine (`crates/vdpi-tun` + `crates/vdpi-ios` -> `VdpiCore.xcframework`), tuned with a dedicated **Low-Memory profile** to stay well below iOS's 50 MB `NEPacketTunnelProvider` Jetsam ceiling.

### iOS Capabilities

- **Shared Rust Userspace TUN Engine:** Uses `NEPacketTunnelFlow` packet bridging (100% public Apple APIs) into `vdpi`'s 7-stage adaptive TLS desync engine, anti-poisoning RFC 8484 DoH ring, clean UDP/443 QUIC fallback, and Cone-NAT UDP relay.
- **50 MB Jetsam-Safe & `RLIMIT_NOFILE`-Safe Profile (`LowMemory`):** Runs with 2 Tokio workers, 16 KB `smoltcp` TCP buffers (vs. 64 KB on Android `Standard`), capped concurrent flows (48 TCP / 64 UDP / 24 DNS inflight), drained `autoreleasepool` outbound callbacks, and Darwin `SO_NOSIGPIPE` protection so background extensions stay rock-solid.
- **Clean RFC 2544 Addressing, LAN Exclusion & Automatic IPv6 Gating:** Uses `198.18.0.2/24` with virtual DNS `198.18.0.1` and distinct remote endpoint `198.19.0.1` (MTU `1400`), excludes all RFC 1918 / loopback / broadcast / link-local / ULA LAN ranges, automatically disables IPv6 tunnel routes on IPv4-only networks via `getifaddrs`, and observes `NWPathMonitor` to flush caches on Wi-Fi/Cellular handoffs.
- **On-Demand VPN & Domain Bypass:** Supports iOS VPN On-Demand (`NEOnDemandRuleConnect`) and custom domain bypass rules. Note: consumer iOS restricts per-app VPN split-tunneling (`NEAppRule`) to supervised MDM devices, so consumer builds use domain bypass.
- **Live Telemetry, Diagnostics & Logs:** App Group (`group.com.vulninc.vdpi`) shares settings while `NETunnelProviderSession.sendProviderMessage` IPC handles 1 Hz telemetry, live reloads, cache clears, and in-tunnel `rustls` TLS 1.3/1.2 Diagnostics.

> **iOS signing, Simulator & physical-device testing caveats:**
> - **CI & Simulator:** `VdpiCore.xcframework` builds, unit tests (`VdpiSharedTests`), and unsigned `generic/platform=iOS` Release compilation are verified in GitHub Actions on `macos-latest`. iOS Simulator does **not** execute `NEPacketTunnelProvider` packet routing — live on-device DPI bypass testing requires a physical iPhone/iPad.
> - **Physical device provisioning:** Installing a `NEPacketTunnelProvider` on a physical iPhone/iPad requires a paid Apple Developer Program account ($99/yr) to provision the `com.apple.developer.networking.networkextension` (`packet-tunnel-provider`) entitlement, and no signed `.ipa` is published to GitHub Releases. Prebuilt `VdpiCore.xcframework.zip` is uploaded as the `ios-xcframework` GitHub Actions artifact.

---

## Desktop Features & Launcher

| Capability | Details |
| :--- | :--- |
| **Single-Binary Self-Installer** | `vdpi install` and `vdpi uninstall` detect your OS automatically — no external `.bat` or `.sh` scripts required. |
| **Native OS Background Services** | Installs as a native **Windows Service (`AUTO_START`)**, **macOS `LaunchAgent`**, or **Linux `systemd --user`** unit. |
| **7-Stage Adaptive Auto-Heal** | Automatically escalates across multi-record TLS splitting, TCP `MSG_OOB` SNI & TLS-framing desync, and 12+ record storms — learning the winning strategy per host and ISP network. |
| **Full App, Voice & Game Support** | Protocol-autodetecting **HTTP/1.1 + HTTPS `CONNECT` + SOCKS5 (`CONNECT` & `UDP ASSOCIATE`) + SOCKS4a** proxy with native OS proxy and environment bridging. |
| **Anti-Poisoning DNS Ring** | In-memory TTL-cached **RFC 8484 DoH** with sticky healthy failover across 4 independent networks (`1.1.1.1`, `8.8.8.8`, `94.140.14.140`, `9.9.9.9`), non-port-53 UDP fallback (`1253`, `443`, `5353`), and sinkhole IP filtering. |
| **100% Desktop VPN Coexistence** | Pure userspace proxy (no WinDivert, kernel extensions, or fake-TTL injection) — coexists seamlessly with WireGuard, Cloudflare WARP, OpenVPN, Mullvad, and ProtonVPN. |
| **Smart Local & Portal Bypass** | Automatically bypasses LAN/private subnets (`localhost`, `10.0.0.0/8`, `192.168.0.0/16`, `*.local`), government/banking portals, and any custom `--bypass` rules. |

### Interactive Launcher

Open `vdpi.exe` from File Explorer, or run `vdpi` with no arguments in an interactive terminal. The launcher offers three choices:

- **Run directly:** Start `vdpi` in the foreground. Closing it stops `vdpi` and releases its desktop proxy automatically.
- **Install for automatic startup:** Register a background service that runs independently of the launcher window.
- **Quit:** Leave without starting or saving a preference.

Use **Up/Down** or **Tab** to move, **Enter** to select, and **Esc** to quit (press **1** to run directly or **2** to install; falls back to a numbered prompt when `TERM=dumb`). **Run directly** saves your preference as `run-directly` next to the executable; use `vdpi launcher` to reopen the chooser or `vdpi start` to skip it.

> **Windows desktop games & `libcurl` apps (e.g., Roblox):** Browsers (Chrome/Edge) and Discord use Windows WinINET proxy settings, whereas native game clients like `RobloxPlayerBeta.exe` use `libcurl` (which ignores WinINET and reads `HTTP_PROXY`/`HTTPS_PROXY`) or WinHTTP. `vdpi` now leases **both** WinINET and `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` in Windows foreground mode (automatically restoring both when closed, even if the console is killed) and additionally configures WinHTTP in `vdpi install` service mode. If Chrome was **already open** before you started `vdpi` in foreground mode, restart Chrome once so games launched via `roblox-player://` inherit `HTTPS_PROXY` — or run `vdpi install` once so `HTTPS_PROXY` is present from login.

<details>
<summary>Cleaning up stale proxy settings from older Windows builds</summary>

If an older Windows build left a dead proxy behind, open **Settings > Network & internet > Proxy** and disable the manual proxy only if it points to `vdpi`'s old local address. If `HTTP_PROXY` or `HTTPS_PROXY` still points there in your user environment, remove those values and reopen affected apps.

</details>

---

## Desktop Installation

Download the release archive for your OS from **[Releases](https://github.com/Vuln-Inc/vdpi/releases/latest)**, extract it, and run `vdpi install`.  
Binary installation, `PATH` registration, background service setup, and OS proxy configuration are handled natively by `vdpi`.

### Windows (Windows 10 & 11 `x86_64`)

Download **[`vdpi-windows-x86_64.zip`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-windows-x86_64.zip)**, extract it, and run in PowerShell or Command Prompt:

```powershell
# Install as a native Windows Service (auto-prompts UAC, starts at boot, adds to System PATH)
.\vdpi.exe install

# Or run for the current session only (no Admin required; Ctrl+C restores proxies)
.\vdpi.exe start

# Stop & remove the Windows Service, clean files & PATH, and restore Windows proxies
vdpi uninstall
```

### macOS (Apple Silicon & Intel)

Download **[`vdpi-macos-universal.tar.gz`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-macos-universal.tar.gz)**, extract it, and run:

```bash
tar -xzf vdpi-macos-universal.tar.gz

# Install to ~/.vdpi/bin/vdpi, codesign, register LaunchAgent, and configure proxies
./vdpi install

# Or run for the current terminal session only (Ctrl+C restores proxies)
./vdpi start

# Stop LaunchAgent, remove files, and restore macOS network settings
vdpi uninstall
```

### Linux (`x86_64` & `arm64`)

Download **[`vdpi-linux-x86_64.tar.gz`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-linux-x86_64.tar.gz)** (or **[`vdpi-linux-arm64.tar.gz`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-linux-arm64.tar.gz)**), extract it, and run:

```bash
tar -xzf vdpi-linux-x86_64.tar.gz

# Install static musl binary to ~/.vdpi/bin/vdpi, enable systemd --user service, and configure proxies
./vdpi install

# Or run in the foreground for the current session (Ctrl+C restores proxies)
./vdpi start

# Disable systemd --user service, remove files, and restore GNOME / KDE proxies
vdpi uninstall
```

### What `vdpi install` Configures

| Platform | Binary Path | Startup Service | System Proxy Integration |
| :--- | :--- | :--- | :--- |
| **Windows** | `%ProgramFiles%\vdpi\bin\vdpi.exe` (added to System `PATH`) | Native Windows Service (`vdpi`, `AUTO_START`, `Tcpip` dependency, crash auto-restart) | Interactive `HKU` / `HKCU` WinINET Registry + `HTTP_PROXY`/`HTTPS_PROXY` User Env + WinHTTP (`netsh winhttp`) + `WTS_SESSION_LOGON` instant sync |
| **macOS** | `~/.vdpi/bin/vdpi` (ad-hoc `codesign`, added to shell `PATH`) | `~/Library/LaunchAgents/com.vdpi.plist` (`RunAtLoad` + `KeepAlive`) | `networksetup` (Wi-Fi / Ethernet, VPN-safe) + `launchctl setenv` (`HTTP_PROXY`/`HTTPS_PROXY` unless `--no-env-proxy`) |
| **Linux** | `~/.vdpi/bin/vdpi` (static `musl`, symlinked to `~/.local/bin/vdpi`) | `~/.config/systemd/user/vdpi.service` (`systemctl --user`) | GNOME `gsettings` + KDE `kioslaverc` + `systemctl --user set-environment` (unless `--no-env-proxy`) |

---

## How It Works

### Adaptive 7-Stage TLS Engine

Shared across desktop, Android, and iOS, every outbound TLS handshake validates the upstream `ServerHello` (`0x16 0x03`) — rejecting TCP resets, TLS Alerts (`0x15`), and injected ISP block pages — and automatically escalates, caches, and self-heals across networks:

| Stage | Strategy | How It Works |
| :---: | :--- | :--- |
| **1** | `ComboMultiRecord` | Splits the TLS `ClientHello` into 4 wire-paced RFC-compliant `0x16` records across the handshake header and SNI midpoint (defeating OS TCP coalescing and shallow DPI). |
| **2** | `OobSniDesync` | Injects 1 TCP Out-of-Band (`MSG_OOB`, `URG=1`) decoy byte right at the SNI midpoint. Server TCP stacks (`SO_OOBINLINE=0`) strip the urgent byte seamlessly while stateful DPI boxes see a corrupted hostname and pass the flow through. |
| **3** | `MultiRecordOob` | Combines 4-record TLS splitting with a `MSG_OOB` urgent decoy byte at the TLS record boundary inside SNI, shifting subsequent TLS record framing for stateful DPI state machines. |
| **4** | `FineFragment` | Keeps a single intact outer TLS record split across 4 wire-paced TCP segments (for strict servers or firewalls that reject multi-record `ClientHello`s or strip `URG`). |
| **5** | `DeepRecordStorm` | Emits 12+ wire-paced `0x16` records (10 tiny 2-byte lead records exhausting hardware DPI per-flow packet caps before the SNI hits the wire, followed by SNI-split records) and auto-promotes globally on strict stateful ISPs. |
| **6** | `SlowSniSlice` | Single intact outer TLS record with 2-byte paced SNI slicing and a 20ms midpoint gap for strict servers behind stateful burst-reassembling DPI. |
| **7** | `DirectPassthrough` | Falls back cleanly to an unmodified handshake for unblocked strict WAFs and caches the winning strategy per hostname. |

### Network Compatibility

`vdpi` works across ISPs, fiber, cable, and mobile carriers worldwide without region-specific configs or manual DNS changes:

| DPI / Censorship Mechanism | Automatic `vdpi` Countermeasure |
| :--- | :--- |
| **Active Inline & Stateful Stream-Reassembling DPI** | 7-Stage wire-paced adaptive TLS engine (`ComboMultiRecord` -> `OobSniDesync` -> `MultiRecordOob` -> `FineFragment` -> `DeepRecordStorm` -> `SlowSniSlice`) with automatic ISP-wide promotion |
| **Transparent Port-53 DNS Hijacking & Poisoning** | Sticky multi-ASN IP-literal RFC 8484 DoH ring with concurrent failover, negative caching, 30s circuit-breaker to non-port-53 UDP (`1253`, `443`, `5353`), and sinkhole IP rejection |
| **SNI, HTTP `Host`, IPv6 CNAME & QUIC Filtering** | CNAME-safe IPv4/IPv6 resolution, automatic mobile IPv6-availability gating, 3-segment wire-paced HTTP `Host` splitting, and full UDP/443 QUIC blocking (RFC 9000 + RFC 9287 greased + short-header) for clean TCP TLS fallback |
| **Strict CDNs, Banking & Government Portals** | Built-in LAN/government/banking bypass policy (`--bypass` / Android & iOS bypass lists) + Stage 7 Auto-Heal Passthrough |

---

## Diagnostics

On **Android** and **iOS**, tap **Diagnostics** from the main Tunnel screen to run live DoH and real `rustls` TLS 1.3/1.2 probes directly through the desync engine, or inspect/copy the live engine event log.

On **Desktop**, run:

```bash
# Inspect live daemon health, service state, ports, and OS proxy settings
vdpi status

# Run live end-to-end HTTP CONNECT + SOCKS5h + DoH connectivity checks
vdpi doctor
```

<details>
<summary>Example <code>vdpi doctor</code> output</summary>

```text
Testing against running vdpi daemon at 127.0.0.1:8080 (SOCKS5: 127.0.0.1:1080)...

=== HTTP/HTTPS CONNECT Tunnel Checks ===
  [PASS] Discord Web              -> HTTP 200 (  38 ms)
  [PASS] Discord Updater          -> HTTP 200 (  41 ms)
  [PASS] Discord Gateway          -> HTTP 200 (  35 ms)
  [PASS] Discord CDN              -> HTTP 200 (  29 ms)
  [PASS] Discord Voice Latency    -> HTTP 204 (  44 ms)
  [PASS] Roblox Web               -> HTTP 200 (  72 ms)
  [PASS] Roblox ClientSettings    -> HTTP 200 (  51 ms)
  [PASS] Roblox APIs              -> HTTP 404 (  68 ms)
  [PASS] Roblox Auth              -> HTTP 200 (  69 ms)
  [PASS] Roblox GameJoin          -> HTTP 404 (  64 ms)
  [PASS] Roblox Telemetry         -> HTTP 200 (  63 ms)

=== SOCKS5h (Remote DoH + TLS DPI Desync) Checks ===
  [PASS] SOCKS5 Discord           -> HTTP 200 (  37 ms)
  [PASS] SOCKS5 Discord Gateway   -> HTTP 200 (  34 ms)
  [PASS] SOCKS5 Roblox Web        -> HTTP 200 (  70 ms)
  [PASS] SOCKS5 Roblox APIs       -> HTTP 404 (  65 ms)

All Discord & Roblox HTTP CONNECT and SOCKS5h checks passed.
```

</details>

---

## CLI Reference

```text
Usage: vdpi [OPTIONS] [COMMAND]

Commands:
  start      Start the vdpi engine in the foreground without opening the launcher [aliases: run]
  launcher   Open the run or install chooser, even if a preference was saved
  install    Install vdpi and enable automatic background startup (Windows Service / LaunchAgent / systemd)
  uninstall  Stop vdpi, remove startup registration, and restore system proxy settings
  status     Display live daemon health, ports, system proxy state, and session environment
  doctor     Run live end-to-end DPI bypass diagnostics (HTTP CONNECT + SOCKS5h + DoH)
  help       Print this message or the help of the given subcommand(s)
```

<details>
<summary>All CLI options</summary>

```text
Options:
  -b, --bind <BIND>              Local address to bind listeners on [default: 127.0.0.1]
  -p, --port <PORT>              Primary proxy port (HTTP/1.1, HTTPS CONNECT, SOCKS5, SOCKS4a) [default: 8080]
  -s, --socks-port <SOCKS_PORT>  Dedicated SOCKS5 (TCP + UDP) port; 0 to disable [default: 1080]
  -m, --mode <MODE>              DPI desync mode [default: combo] [possible values: combo, tls-record, fragment, split]
  -c, --chunk-size <CHUNK_SIZE>  Segment size (bytes) for fragmented TLS ClientHello packets [default: 10]
      --dns <DNS_ADDR>           Primary upstream DNS / DoH server address or URL [default: 1.1.1.1]
      --dns-port <DNS_PORT>      Port for plain UDP DNS queries when DoH is disabled [default: 53]
  -4, --ipv4-only                Resolve IPv4 (A) records only
      --no-doh                   Disable DNS-over-HTTPS and use plain UDP / OS DNS resolution
      --include <REGEX>          Apply DPI desync only to hostnames matching this regex (repeatable)
      --bypass <DOMAIN>          Additional domains or wildcards to bypass DPI fragmentation (repeatable)
      --no-system-proxy          Do not modify OS system proxy settings
      --no-socks-proxy           Do not configure OS SOCKS5 system proxy (keeps SOCKS5 listener running)
      --no-env-proxy             Do not export proxy variables into the user session environment
      --allow-quic               Allow QUIC (UDP/443) packets over SOCKS5 UDP relay
  -t, --timeout <TIMEOUT_MS>     Outbound TCP connection timeout in ms (0 uses default 8000ms) [default: 0]
  -d, --debug                    Enable verbose debug logging
  -q, --quiet                    Suppress startup banner and informational output
  -h, --help                     Print help
  -V, --version                  Print version
```

</details>

---

## Building from Source

### Desktop Binary

Requires the current stable Rust toolchain:

```bash
git clone https://github.com/Vuln-Inc/vdpi.git
cd vdpi
cargo build --locked --release
cargo test --workspace --locked
./target/release/vdpi install
```

- The desktop proxy allows up to 256 concurrent client sessions across both listeners (with a 15-second negotiation timeout for incomplete HTTP/SOCKS handshakes).
- The default test suite runs offline against local sockets. To run the optional live public DNS smoke test, execute `cargo test --locked resolves_discord_and_roblox_via_live_doh -- --ignored`.

### Android APK

Requires Rust Android targets (`aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`), `cargo-ndk` (v4.1.2+), JDK 21, and Android SDK 35 + NDK 27:

```bash
# 1. Cross-compile libvdpi_android.so for arm64-v8a, armeabi-v7a, and x86_64
./android/scripts/build-native.sh

# 2. Run Android unit tests, release lint, and assemble the universal APK
cd android
./gradlew testDebugUnitTest lintRelease assembleRelease
```

The signed universal APK is written to `android/app/build/outputs/apk/release/app-release.apk`.

### iOS App (Xcode + XCFramework)

Requires macOS with Xcode 16+, `xcodegen` (`brew install xcodegen`), and Rust Apple iOS targets (`aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`):

```bash
# 1. Cross-compile Rust static libs and package ios/Frameworks/VdpiCore.xcframework
./ios/scripts/build-xcframework.sh

# 2. Generate ios/Vdpi.xcodeproj and open in Xcode
cd ios
xcodegen generate
open Vdpi.xcodeproj

# Optional: run unsigned Simulator XCTests and verify generic arm64 Release build from CLI
xcodebuild test -project Vdpi.xcodeproj -scheme VdpiApp -destination 'platform=iOS Simulator,name=iPhone 16' CODE_SIGN_IDENTITY='-' CODE_SIGNING_REQUIRED=NO DEVELOPMENT_TEAM=''
xcodebuild build -project Vdpi.xcodeproj -scheme VdpiApp -configuration Release -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO
```

To sign and install on your own physical iPhone/iPad with your own paid Apple Developer Team, replace the bundle IDs (`com.vulninc.vdpi`, `com.vulninc.vdpi.packet-tunnel`) and App Group (`group.com.vulninc.vdpi`) with your own unique identifiers across all four locations before running `xcodegen generate`:
1. `ios/project.yml` (`bundleIdPrefix` and both `PRODUCT_BUNDLE_IDENTIFIER` values)
2. `ios/VdpiApp/VdpiApp.entitlements` (`com.apple.security.application-groups`)
3. `ios/PacketTunnel/PacketTunnel.entitlements` (`com.apple.security.application-groups`)
4. `ios/Shared/VdpiAppGroup.swift` (`suiteName` and `extensionBundleId`)

<details>
<summary>Repository layout</summary>

```text
vdpi/
├── Cargo.toml                  # Workspace root (vdpi + vdpi-tun + vdpi-android + vdpi-ios)
├── LICENSE                     # MIT License
├── README.md                   # Documentation and installation guide
├── .github/workflows/
│   └── release.yml             # Desktop, Android APK, iOS XCFramework/XCTest, and Release CI
├── src/
│   ├── main.rs                 # CLI entrypoint, Windows SCM dispatch, and signal handling
│   ├── lib.rs                  # Public Rust core exports shared by desktop & mobile
│   ├── config.rs               # CLI flags, desync modes, and runtime configuration
│   ├── launcher.rs             # Interactive launcher state & preference handling
│   ├── launcher/tui.rs         # Terminal launcher UI
│   ├── tls.rs                  # Zero-panic TLS ClientHello SNI parser and record splitter
│   ├── bypass.rs               # LAN, private subnet, regex, and portal bypass policy
│   ├── dns.rs                  # Multi-tier RFC 8484 DoH + port-1253 anti-poisoning DNS resolver
│   ├── desync.rs               # 7-stage adaptive OOB, multi-record, and paced SNI DPI desynchronizer
│   ├── server.rs               # Protocol-autodetecting TCP listener and dual-port SOCKS5 server
│   ├── service.rs              # Cross-platform self-installer, service manager, status, and doctor
│   ├── platform/
│   │   ├── mod.rs              # Cross-platform OS proxy and service abstraction
│   │   ├── windows.rs          # Windows WinINET HKU/HKCU proxy, System PATH, and broadcasts
│   │   ├── windows_service.rs  # Native Windows SCM service dispatcher, UAC elevation, and session sync
│   │   ├── macos.rs            # macOS SystemConfiguration, launchd env, and VPN-aware watchdog
│   │   ├── linux.rs            # Linux systemd --user, GNOME gsettings, and KDE kioslaverc
│   │   └── unix_foreground.rs  # Unix foreground proxy lifecycle cleanup
│   └── proxy/
│       ├── mod.rs              # Proxy protocol dispatch
│       ├── http.rs             # HTTP/1.1 forward proxy, HTTPS CONNECT tunnel, and health probe
│       └── socks.rs            # RFC 1928 SOCKS5 (CONNECT + UDP ASSOCIATE) and SOCKS4a server
├── crates/
│   ├── vdpi-tun/               # Shared pure-Rust mobile userspace TUN stack (smoltcp + doctor)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs          # Unified TelemetrySnapshot and public module exports
│   │       ├── config.rs       # TunnelConfig JSON schema + Standard / LowMemory profiles
│   │       ├── pipeline.rs     # Channel-driven IP/TCP/UDP/DNS pipeline, QUIC blocker, Cone-NAT
│   │       ├── fd.rs           # Unix AsyncFd<OwnedFd> adapter (Android)
│   │       ├── doctor.rs       # Native rustls TLS 1.3/1.2 + DoH connectivity probe runner
│   │       └── events.rs       # Bounded in-memory event ring buffer
│   ├── vdpi-android/           # Thin Android JNI + OwnedFd adapter over vdpi-tun
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs          # Android lifecycle manager (Standard profile)
│   │       └── jni_bridge.rs   # Panic-safe JNI entrypoints for Kotlin
│   └── vdpi-ios/               # Thin iOS C-ABI staticlib adapter over vdpi-tun
│       ├── Cargo.toml
│       ├── include/            # vdpi_ios.h + module.modulemap for VdpiCore.xcframework
│       └── src/
│           ├── lib.rs          # iOS lifecycle manager (LowMemory profile, 2 workers)
│           └── ffi.rs          # Panic-safe extern "C" FFI surface + C-ABI tests
├── android/                    # Native Jetpack Compose Android app (minSdk 26 / targetSdk 35)
│   ├── scripts/build-native.sh # cargo-ndk cross-compilation for arm64-v8a, armeabi-v7a, x86_64
│   └── app/src/main/java/com/vulninc/vdpi/
│       ├── MainActivity.kt     # Compose host and navigation
│       ├── vpn/                # VdpiVpnService (Always-On, reconnect, network callback) & QS Tile
│       ├── engine/             # NativeEngine JNI bindings & Kotlinx models
│       ├── data/               # DataStore settings repository & split-tunnel config
│       └── ui/                 # Tunnel, Apps, and Settings screens + monochrome theme
├── ios/                        # Native SwiftUI iOS app + NEPacketTunnelProvider (iOS 16+)
│   ├── project.yml             # XcodeGen project specification (VdpiApp, VdpiPacketTunnel, Tests)
│   ├── scripts/build-xcframework.sh # Rust iOS + Simulator XCFramework build script
│   ├── Shared/                 # Models, App Group IPC, Formatters, NativeBridge, TunnelNetworkSettings
│   ├── PacketTunnel/           # NEPacketTunnelProvider + NWPathMonitor + Info.plist + Entitlements
│   ├── VdpiApp/                # SwiftUI Tunnel & Settings views, TunnelManager, monochrome theme
│   └── VdpiAppTests/           # XCTest suite verifying wire JSON, IPC, routes, and live Rust FFI
└── tests/
    └── integration_test.rs     # End-to-end TLS desync, auto-heal, SOCKS5/4a, and UDP relay tests
```

</details>

---

## License

Released under the [MIT License](./LICENSE). Copyright © 2026 [Vuln-Inc](https://github.com/Vuln-Inc).
