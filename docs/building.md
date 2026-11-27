# Building from Source

This guide covers the Rust workspace layout and build steps for Desktop (Windows, macOS, Linux), Android (APK), and iOS (XCFramework + Xcode / IPA).

---

## Workspace Crate Layout

`vdpi` is a single Cargo workspace (`resolver = "2"`, Rust 2021 edition) with five crates plus the Android and iOS app projects:

| Path | Crate / Target | Role |
| :--- | :--- | :--- |
| `core/engine` | `vdpi-core` | Pure-Rust anti-DPI core: 7-stage adaptive TLS desync engine, RFC 8484 DoH DNS ring, bypass policy, socket binder, and shared `RuntimeConfig`. |
| `core/tun` | `vdpi-tun` | Shared pure-Rust userspace TUN stack (in-tree `smoltcp` 0.14, `etherparse`, packet pipeline, Cone-NAT UDP relay, TUN diagnostics `doctor`) used by Desktop TUN, Android, and iOS. |
| `core` | `vdpi` | Desktop binary and library: HTTP/HTTPS `CONNECT` + SOCKS5/4a proxy, desktop TUN driver integration, OS background service installer/control, `ratatui` Control Center and live dashboard, and SHA-256 self-updater. |
| `android/native` | `vdpi-android` | Rust JNI + `OwnedFd` bridge (`cdylib` + `rlib`) wrapping `vdpi-core` and `vdpi-tun` for the Android app (`android/app`). |
| `ios/native` | `vdpi-ios` | Rust C-ABI static library (`staticlib` + `rlib`) wrapping `vdpi-core` and `vdpi-tun`, packaged into `VdpiCore.xcframework` for `ios/VdpiApp` and `ios/PacketTunnel`. |

### Repository Tree

```text
vdpi/
├── core/
│   ├── engine/                 # vdpi-core: TLS desync, DoH ring, bypass policy, RuntimeConfig
│   ├── tun/                    # vdpi-tun: shared userspace TUN stack (smoltcp, packet, pipeline, doctor)
│   ├── src/                    # vdpi desktop CLI, proxy/, platform/, service, launcher/, tui_dashboard, update
│   └── tests/                  # End-to-end TLS desync, auto-heal, SOCKS5/4a, UDP relay, service tests
├── android/
│   ├── app/                    # Kotlin Jetpack Compose UI, VpnService, DataStore, Home Screen widget
│   ├── native/                 # vdpi-android: Rust JNI bridge over vdpi-tun
│   └── scripts/                # build-native.sh (cargo-ndk for arm64-v8a, armeabi-v7a, x86_64)
├── ios/
│   ├── VdpiApp/                # SwiftUI app, FloatingChrome, TunnelManager, Siri Shortcuts (AppIntents)
│   ├── PacketTunnel/           # NEPacketTunnelProvider + NWPathMonitor + entitlements
│   ├── Shared/                 # Models, VdpiAppGroup (dynamic IPC), Formatters, NativeBridge, UpdateChecker
│   ├── VdpiAppTests/           # XCTest suite verifying wire JSON, IPC, routes, and live Rust FFI
│   ├── native/                 # vdpi-ios: Rust C-ABI staticlib bridge + C headers over vdpi-tun
│   ├── scripts/                # build-xcframework.sh (iOS device + Simulator XCFramework)
│   └── project.yml             # XcodeGen project specification
├── docs/                       # Reference guides (engines.md, vpn-and-bypass.md, cli.md, diagnostics.md, building.md)
├── .github/workflows/          # release.yml (Desktop, Android APK, iOS XCFramework/XCTest/IPA CI)
├── Cargo.toml                  # Rust workspace root (default-members = ["core"])
└── Cargo.lock
```

---

## Desktop Binary (Windows, macOS, Linux)

### Prerequisites

- Current stable Rust toolchain (`rustup`, `cargo`).

### Standard Build and Test

```bash
git clone https://github.com/Vuln-Inc/vdpi.git
cd vdpi
cargo build --locked --release
cargo test --workspace --locked
./target/release/vdpi install
```

Optional lint and live DNS checks:

```bash
# Workspace Clippy check (enforced in CI)
cargo clippy --workspace --locked --all-targets -- -D warnings

# Optional live public DoH smoke test (default test suite runs offline against local sockets)
cargo test -p vdpi-core --locked resolves_discord_and_roblox_via_live_doh -- --ignored
```

> Runtime note: The desktop proxy allows up to 256 concurrent client sessions across both listeners (with a 15-second negotiation timeout for incomplete HTTP/SOCKS handshakes).

### Windows (`x86_64-pc-windows-msvc`) and `wintun.dll`

```powershell
cargo build --locked --release --target x86_64-pc-windows-msvc
```

The compiled binary is written to `target\x86_64-pc-windows-msvc\release\vdpi.exe` (or `target\release\vdpi.exe` when building for the host default target).

#### `wintun.dll` Placement (Required for Windows TUN Mode)

Desktop TUN mode on Windows (`--tun` / `engine = "tun"`) loads the signed WireGuard **Wintun** user-mode driver DLL (`wintun.dll`, `amd64` build from [wintun.net](https://www.wintun.net/)):

- **Local development / portable runs**: Place `wintun.dll` in the same directory as `vdpi.exe` (e.g., `target\release\wintun.dll`).
- **Installed Windows Service (`vdpi install`)**: Place `wintun.dll` alongside the installed executable at `%ProgramFiles%\vdpi\bin\wintun.dll`.
- **Proxy mode (`--proxy`)**: Does not require `wintun.dll`.

### macOS (Apple Silicon & Intel Universal)

```bash
rustup target add aarch64-apple-darwin x86_64-apple-darwin

cargo build --locked --release --target aarch64-apple-darwin
cargo build --locked --release --target x86_64-apple-darwin

lipo -create -output vdpi \
  target/aarch64-apple-darwin/release/vdpi \
  target/x86_64-apple-darwin/release/vdpi
chmod 755 vdpi
codesign -fs - vdpi
```

macOS TUN mode uses the built-in kernel `utun` interface (no third-party kernel extension required; elevated privileges / `LaunchDaemon` are required to open `utun` and manage routes).

### Linux (`x86_64` & `arm64` Static `musl`)

Install static musl build tools (Debian/Ubuntu example) and Rust targets:

```bash
sudo apt-get update
sudo apt-get install -y musl-tools gcc-aarch64-linux-gnu
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

# x86_64 static binary
cargo build --locked --release --target x86_64-unknown-linux-musl

# arm64 static binary
CC_aarch64_unknown_linux_musl=aarch64-linux-gnu-gcc \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
cargo build --locked --release --target aarch64-unknown-linux-musl
```

Linux TUN mode uses `/dev/net/tun` and requires `CAP_NET_ADMIN` or root privileges.

---

## Android APK

### Prerequisites

- Rust Android targets:
  ```bash
  rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
  ```
- `cargo-ndk` v4.1.2+:
  ```bash
  cargo install cargo-ndk --version 4.1.2 --locked
  ```
- JDK 21 (e.g. Eclipse Temurin 21)
- Android SDK 35 (`platforms;android-35`, `build-tools;35.0.0`) and Android NDK 27 (`ndk;27.2.12479018`) with `ANDROID_NDK_HOME` pointing to the NDK directory.

### Build Steps

```bash
# 1. Cross-compile libvdpi_android.so for arm64-v8a, armeabi-v7a, and x86_64 (API 26+)
./android/scripts/build-native.sh

# 2. Run Android unit tests, release lint, and assemble the universal APK
cd android
./gradlew testDebugUnitTest lintRelease assembleRelease
```

The universal APK is written to:

```text
android/app/build/outputs/apk/release/app-release.apk
```

### Android Release Signing

To sign with your own release keystore (enabling in-place updates without reinstalling), export these environment variables before invoking `./gradlew assembleRelease`:

- `VDPI_KEYSTORE_PATH` - path to the `.jks` keystore file
- `VDPI_KEYSTORE_PASSWORD` - keystore password
- `VDPI_KEY_ALIAS` - key alias inside the keystore
- `VDPI_KEY_PASSWORD` - key password

Official GitHub Releases starting with `v0.4.1` are signed with the persistent repository keystore (`VDPI_KEYSTORE_BASE64`).

---

## iOS IPA (XCFramework + XcodeGen)

### Prerequisites

- macOS with Xcode 16+
- `xcodegen` (`brew install xcodegen`)
- `ldid-procursus` (`brew install ldid-procursus`) - only needed if packaging an ad-hoc unsigned IPA for TrollStore / third-party signers
- Rust Apple iOS targets (installed automatically by `build-xcframework.sh`):
  `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`

### Build Steps

```bash
# 1. Cross-compile Rust static libs (iOS 16.0+) and package ios/Frameworks/VdpiCore.xcframework
./ios/scripts/build-xcframework.sh

# 2. Generate ios/Vdpi.xcodeproj and open in Xcode
cd ios
xcodegen generate
open Vdpi.xcodeproj
```

### Optional CLI Simulator Tests and Release Build

```bash
cd ios

# Run unsigned XCTests on iOS Simulator
xcodebuild test \
  -project Vdpi.xcodeproj \
  -scheme VdpiApp \
  -destination 'platform=iOS Simulator,name=iPhone 16' \
  CODE_SIGN_IDENTITY='-' \
  CODE_SIGNING_REQUIRED=NO \
  DEVELOPMENT_TEAM=''

# Verify generic arm64 physical-device Release build without signing
xcodebuild build \
  -project Vdpi.xcodeproj \
  -scheme VdpiApp \
  -configuration Release \
  -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO
```

### Packaging an Unsigned IPA (TrollStore / External Re-Signers)

To reproduce the release `vdpi-ios-unsigned.ipa` locally after running `xcodebuild build ... -derivedDataPath build`:

```bash
APP_PATH="build/Build/Products/Release-iphoneos/VdpiApp.app"
APPEX_PATH="$APP_PATH/PlugIns/VdpiPacketTunnel.appex"

# Embed ad-hoc arm64 entitlements and signing identifiers (preserved by TrollStore; replaced cleanly by re-signers)
ldid -Icom.vulninc.vdpi.packet-tunnel -SPacketTunnel/PacketTunnel.entitlements "$APPEX_PATH/VdpiPacketTunnel"
ldid -Icom.vulninc.vdpi -SVdpiApp/VdpiApp.entitlements "$APP_PATH/VdpiApp"

mkdir -p ipa-stage/Payload
cp -R "$APP_PATH" ipa-stage/Payload/VdpiApp.app
(cd ipa-stage && zip -qry ../vdpi-ios-unsigned.ipa Payload)
```

### Signing for a Physical iPhone / iPad (Paid Apple Developer Team)

To build and sign directly in Xcode with your own paid Apple Developer Team, replace the bundle IDs (`com.vulninc.vdpi`, `com.vulninc.vdpi.packet-tunnel`) and App Group (`group.com.vulninc.vdpi`) with your own unique identifiers across **these three files** before running `xcodegen generate`:

1. `ios/project.yml` - `bundleIdPrefix` and both `PRODUCT_BUNDLE_IDENTIFIER` values
2. `ios/VdpiApp/VdpiApp.entitlements` - `com.apple.security.application-groups`
3. `ios/PacketTunnel/PacketTunnel.entitlements` - `com.apple.security.application-groups`

No Swift source changes are needed: since `v0.4.1`, `ios/Shared/VdpiAppGroup.swift` automatically detects `suiteName` from `embedded.mobileprovision` and `extensionBundleId` from `PlugIns/*.appex/Info.plist` at runtime.

> **Signing and Simulator caveats:**
> - **Free Apple IDs cannot sign the VPN extension**: Apple restricts the `com.apple.developer.networking.networkextension` (`packet-tunnel-provider`) entitlement to paid Apple Developer accounts (or TrollStore on supported iOS versions).
> - **iOS Simulator limitation**: iOS Simulator validates unit tests (`VdpiSharedTests`) and Rust FFI bindings, but does not execute `NEPacketTunnelProvider` packet routing. Live on-device DPI bypass requires a physical iPhone or iPad.
