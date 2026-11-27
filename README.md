<div align="center">

**English** · [Türkçe](./README.tr.md)

# `vdpi`

Self-healing anti-DPI engine in Rust, native across Windows, macOS, Linux, Android, and iOS.  
Ships as a native Desktop GUI, an interactive Control Center TUI, and zero-root mobile apps - running as a transparent system-wide TUN adapter or a lightweight local proxy with zero remote servers and zero telemetry.

[![Release](https://img.shields.io/badge/Release-v0.6.2-38bdf8?style=for-the-badge&logo=github)](https://github.com/Vuln-Inc/vdpi/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-34d399?style=for-the-badge)](./LICENSE)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20Android%20%7C%20iOS-818cf8?style=for-the-badge)](#quick-install)

[Quick Install](#quick-install) · [Engines](#engine-modes-proxy-vs-tun) · [Getting Started](#getting-started) · [Docs](#documentation) · [Releases](https://github.com/Vuln-Inc/vdpi/releases/latest) · [Changelog](./CHANGELOG.md) · [Security](./SECURITY.md)

</div>

<p align="center">
  <img src="docs/screenshots/desktop-gui-overview.png" alt="vdpi Desktop GUI Overview with live throughput chart, TUN/Proxy switch, DNS status, and active connections" width="49%">
  <img src="docs/screenshots/desktop-gui-split.png" alt="vdpi Desktop GUI Split Tunneling with routing modes, quick presets, and companion app detection" width="49%">
</p>

<p align="center">
  <img src="docs/screenshots/hero-showcase.png" alt="vdpi Live Dashboard, Control Center TUI, and mobile app" width="100%">
</p>

<p align="center">
  <img src="docs/screenshots/tui-showcase.png" alt="vdpi doctor diagnostics and TUI DNS server picker" width="49%">
  <img src="docs/screenshots/mobile-showcase.png" alt="vdpi mobile Settings, Tunnel status, and Diagnostics" width="49%">
</p>

---

## Highlights

<table>
  <tr>
    <td valign="top" width="50%">
      <strong>Native Desktop GUI</strong><br>
      Lightweight native app for Windows, macOS, and Linux with live 60s throughput telemetry, 1-click TUN/Proxy switching, visual per-app Split Tunneling (with quick presets for Discord, Roblox, Valorant &amp; Riot, Steam, browsers, and OBS plus companion process grouping), DNS &amp; domain rules, Diagnostics, and system tray / menu bar controls.
    </td>
    <td valign="top" width="50%">
      <strong>Two desktop engines (TUN + Proxy)</strong><br>
      Transparent system-wide TUN (<code>Wintun</code> / <code>utun</code> / <code>/dev/net/tun</code>, zero proxy env edits or browser restarts) or classic lightweight local HTTP/SOCKS5 proxy (no virtual adapter, portable) - 1-click or 1-press switchable.
    </td>
  </tr>
  <tr>
    <td valign="top" width="50%">
      <strong>Native across all 5 platforms</strong><br>
      Native Desktop GUI packages and lightweight CLI binaries on Windows, macOS, and Linux, plus zero-root local VPN apps for Android (APK) and iOS/iPadOS (IPA) sharing the same Rust core.
    </td>
    <td valign="top" width="50%">
      <strong>English &amp; Turkish (<code>Türkçe</code>) support</strong><br>
      Full English and Turkish localization across the Desktop GUI, Control Center TUI, Android, and iOS - auto-detected from your system locale or switchable anytime in Settings or <code>config.toml</code>.
    </td>
  </tr>
  <tr>
    <td valign="top" width="50%">
      <strong>Zero-hassle &amp; lightweight</strong><br>
      Self-healing 7-stage adaptive TLS desync engine, anti-poisoning RFC 8484 DoH ring, UDP/443 QUIC blocking, ~10-20 MB RAM, and crash-proof OS teardown.
    </td>
    <td valign="top" width="50%">
      <strong>VPN, audio &amp; gaming safe</strong><br>
      Gigabit TUN with zero-audio-stutter thread budgeting (VoiceMeeter safe), auto-yields to Mullvad, WireGuard, OpenVPN, ProtonVPN, and WARP and auto-resumes; coexists with Tailscale, Docker, and LAN; WHQL-signed Wintun (anticheat safe) and low-latency UDP NAT for Discord, Roblox, and games.
    </td>
  </tr>
  <tr>
    <td valign="top" width="50%">
      <strong>Control Center TUI</strong><br>
      Interactive <code>ratatui</code> launcher with <strong>Open live dashboard</strong> (<code>l</code>, attach live without restarting), <strong>Choose DNS server</strong> (<code>d</code>, presets + <code>[7] Custom DNS</code> IP/DoH picker), per-app <strong>Split tunneling</strong> picker (<code>s</code>, fuzzy search + Include/Exclude), SHA-256-verified self-updater (<code>vdpi update</code>), and <code>config.toml</code> persistence.
    </td>
    <td valign="top" width="50%">
      <strong>Local-only &amp; verifiable</strong><br>
      All traffic stays on-device with no remote relay servers or analytics. Every release asset is verified against <code>SHA256SUMS.txt</code> (see <a href="https://github.com/Vuln-Inc/vdpi/blob/main/SECURITY.md#binary-verification">SECURITY.md</a>).
    </td>
  </tr>
</table>

---

## Quick Install

### Which Download Should I Pick?

`vdpi` ships in three editions that all share the same local Rust engine and `config.toml` - pick the one that fits how you use your device (most desktop users only need the **Desktop App**):

| Edition | Best for | Release file pattern | What's inside |
| :--- | :--- | :--- | :--- |
| **Desktop App (GUI)** *(Recommended)* | Most Windows, macOS & Linux users | `vdpi-desktop-*` (`.zip`, `.dmg`, `.deb`, `.AppImage`) | Native app window, system tray, visual Split Tunneling, DNS/Diagnostics, **plus** bundled `vdpi` engine & `wintun.dll` |
| **Terminal / TUI (CLI)** | Terminal users, scripts, headless or ARM64 Linux | `vdpi-*` (`.zip`, `.tar.gz`) | Lightweight terminal Control Center TUI & background service CLI (no GUI window) |
| **Mobile** | Phones & tablets | `vdpi-android-*.apk`, `vdpi-ios-*.ipa` | Zero-root local VPN app for Android `8.0+` and iOS/iPadOS `16+` |

> **Tip:** If you download the **Desktop App (GUI)**, you do **not** need the Terminal / TUI archive separately - everything is already bundled.

### Desktop App (GUI) - Windows, macOS & Linux

- **Windows (`x86_64`, Windows 10 & 11):** [`vdpi-desktop-windows-x86_64-portable.zip`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-desktop-windows-x86_64-portable.zip) (unzip and run `vdpi-desktop.exe`)
- **macOS (Universal, Apple Silicon & Intel):** [`vdpi-desktop-macos-universal.dmg`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-desktop-macos-universal.dmg) (open DMG and drag to Applications)
- **Linux (`x86_64`):** [`vdpi-desktop-linux-x86_64.deb`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-desktop-linux-x86_64.deb) (Debian/Ubuntu) · [`vdpi-desktop-linux-x86_64.AppImage`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-desktop-linux-x86_64.AppImage) (any distro)

> **Note:** Desktop GUI packages bundle the `vdpi` engine binary (and the unmodified WHQL-signed `wintun.dll` `0.14.1` on Windows), integrate with the system tray / menu bar, and share the same `config.toml` and background service as the Terminal / TUI edition.

### Terminal / TUI (CLI) - Windows (`x86_64`, Windows 10 & 11)

```powershell
# PowerShell one-liner (SHA-256 verified)
irm https://vuln-inc.github.io/vdpi/install.ps1 | iex

# Scoop (direct manifest, no extra bucket required)
scoop install https://vuln-inc.github.io/vdpi/vdpi.json

# WinGet *(pending review: microsoft/winget-pkgs#489148)*
winget install Vuln-Inc.vdpi

# Cargo (https://crates.io/crates/vdpi)
cargo install vdpi
```

> **Note:** Official Windows CLI releases (`vdpi-windows-x86_64.zip`) ship `vdpi.exe` alongside the unmodified WHQL-signed `wintun.dll` (`0.14.1`) and `WINTUN-LICENSE.txt` (needed only for TUN mode). Proxy mode uses a fail-open `/vdpi.pac` auto-config proxy across Windows (`AutoConfigURL`), macOS (`AutoProxyURL`), and Linux (GNOME/KDE PAC; Linux also exports user-session `HTTP_PROXY`/`HTTPS_PROXY` unless `--no-env-proxy` is set), so terminating or crashing `vdpi` on Windows/macOS never bricks direct internet access. `cargo install vdpi` works in Proxy mode immediately; for TUN mode on Windows, copy `wintun.dll` from the matching release zip beside `vdpi.exe`.

Direct download: [`vdpi-windows-x86_64.zip`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-windows-x86_64.zip) (`vdpi.exe`, WHQL-signed `wintun.dll` `0.14.1`, and `WINTUN-LICENSE.txt`) or [crates.io/crates/vdpi](https://crates.io/crates/vdpi).

### Terminal / TUI (CLI) - macOS & Linux (`universal` / `x86_64` & `arm64`)

```bash
# Shell one-liner (macOS & Linux, SHA-256 verified)
curl -fsSL https://vuln-inc.github.io/vdpi/install.sh | sh

# Cargo (https://crates.io/crates/vdpi)
cargo install vdpi
```

Direct downloads: [`vdpi-macos-universal.tar.gz`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-macos-universal.tar.gz) · [`vdpi-linux-x86_64.tar.gz`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-linux-x86_64.tar.gz) · [`vdpi-linux-arm64.tar.gz`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-linux-arm64.tar.gz) (static `musl`).

### Android (`8.0+`, `arm64-v8a` / `armeabi-v7a` / `x86_64`)

- Download the signed universal APK: [`vdpi-android-universal.apk`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-android-universal.apk)
- Track automatic updates with [Obtainium](https://github.com/ImranR98/Obtainium) using `https://github.com/Vuln-Inc/vdpi`
- Open **vdpi**, tap **Connect**, and run **Diagnostics** to verify DoH and TLS bypass.

### iOS / iPadOS (`16+`, `arm64`)

- **AltStore / SideStore / Feather source URL:**
  ```text
  https://vuln-inc.github.io/vdpi/apps.json
  ```
- **TrollStore / Sideloadly / paid signer:** download [`vdpi-ios-unsigned.ipa`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-ios-unsigned.ipa) (requires TrollStore or a paid Apple Developer certificate with `NetworkExtension` entitlements; free Apple IDs cannot sign `packet-tunnel-provider`).

---

## Engine Modes (Proxy vs TUN)

- **Proxy mode (default):** Zero admin privileges required for portable/foreground runs (and unprivileged background services on macOS/Linux; Admin only for Windows Service install), zero virtual adapter, routing table, or DNS changes, and most stable out of the box for browsers, Discord, Telegram, and apps that honor system proxy.
- **TUN mode (system-wide):** Captures all TCP & UDP traffic including games (Roblox, Valorant, etc.) and apps that ignore system proxy.
- **How to switch:** Toggle **TUN / Proxy** directly in the Desktop GUI Overview, open the `vdpi` Control Center (`vdpi` with no args) and select **Switch to TUN** / **Switch to Proxy** (automatically prompts for UAC on Windows or `sudo` / Touch ID / `pkexec` on macOS & Linux - no need to pre-run as root), or run `vdpi install --tun` / `vdpi --tun`.

| Dimension | Proxy Mode (`--proxy`, **Default**) | TUN Mode (`--tun`) |
| :--- | :--- | :--- |
| **Traffic capture** | Local `127.0.0.1:8080` (HTTP/HTTPS/SOCKS5/4a) + `:1080` (SOCKS5 TCP/UDP) | Layer 3 virtual NIC (`Wintun` / `utun` / `/dev/net/tun`) + userspace stack |
| **App coverage** | Browsers, Discord, Telegram & apps honoring OS fail-open PAC (`/vdpi.pac`) or explicit local proxy listeners | System-wide TCP & UDP: games (Roblox, Valorant, etc.), Discord voice, CLI, all apps |
| **OS integration** | Fail-open `/vdpi.pac` auto-config (Windows `AutoConfigURL` & macOS `AutoProxyURL` with zero env vars; Linux GNOME/KDE PAC plus optional `systemd --user` env vars, disabled via `--no-env-proxy`); no virtual adapter, route, or DNS changes | Zero proxy edits; no browser restart required |
| **Privileges & memory** | Zero admin for portable/foreground (unprivileged service on macOS/Linux; Admin only for Windows Service install); ~8-14 MB RAM | Prompts for UAC (Windows) or `sudo` / Touch ID / `pkexec` (macOS & Linux); ~16-22 MB RAM |
| **VPN & anticheat** | Pure loopback proxy; no virtual adapter; `VpnGuard` auto-yield | `VpnGuard` 0ms auto-yield; WHQL-signed Wintun (anticheat safe) |

### Switching Modes

Your current mode (`Proxy` or `TUN`) is always shown in the Desktop GUI Overview and sidebar, in the `Engine` row of the `vdpi` Control Center, and in the Live Dashboard status bar.

- **Desktop GUI:** Click **TUN** or **Proxy** in the Overview header to switch engines immediately.
- **Interactive TUI:** Run `vdpi` with no args and select **Switch to TUN** / **Switch to Proxy** - `vdpi` automatically prompts for elevation (UAC on Windows, `sudo` / Touch ID on macOS & Linux; no need to pre-run as root).
- **CLI:**
  ```bash
  vdpi engine         # Show current engine mode (Proxy or TUN)
  vdpi engine tun     # Switch to transparent system-wide TUN mode
  vdpi engine proxy   # Switch back to default local HTTP/SOCKS5 proxy mode
  vdpi install --tun  # Install background service directly in TUN mode
  vdpi --tun          # Launch or run in TUN mode
  vdpi --tun start    # Run a one-off foreground TUN session
  vdpi --proxy start  # Run a one-off foreground Proxy session
  ```

For anti-DPI framing modes (`--mode combo` default with 7-stage self-healing auto-escalation, `tls-record`, `fragment`, `split`), see [Engine Modes](docs/engines.md) and [CLI Reference](docs/cli.md).

---

## Language Support

`vdpi` supports **English** and **Turkish (`Türkçe`)** across the Desktop GUI, Control Center TUI, Android, and iOS.

- **Automatic detection:** By default, `vdpi` follows your OS locale and launches in Turkish when your system language is set to Turkish, or English otherwise.
- **Manual override:** Switch languages anytime in **Settings** (Desktop GUI, Android, and iOS), inside the Control Center TUI, or by setting `language` in `config.toml` (`"auto"`, `"en"`, or `"tr"`).

---

## Getting Started

Launch **vdpi Desktop** for the graphical interface, or use the CLI and Control Center TUI directly:

```bash
vdpi              # Open the Control Center TUI (`l` live dashboard, `d` DNS picker, `s` Split tunneling, switch engine)
vdpi dashboard    # Attach the live throughput & telemetry dashboard to the running background service
vdpi dns          # Show or switch upstream DNS / DoH server (e.g. `vdpi dns cloudflare`, `vdpi dns 94.140.14.14`)
vdpi split        # Open the per-app Split tunneling picker (alias `vdpi apps`; `--split-mode`, `--split-app`)
vdpi engine tun   # Switch desktop engine to TUN mode (or `vdpi engine proxy`)
vdpi pause        # Temporarily pause the background service (`vdpi resume` to re-enable)
vdpi doctor       # Run live end-to-end DPI bypass and DoH diagnostics
vdpi update       # Check, SHA-256 verify, and upgrade in place
```

Run `vdpi install` to register automatic background startup (Windows Service, macOS `LaunchDaemon` / `LaunchAgent`, or Linux `systemd`), `vdpi start` for a foreground session with a live throughput sparkline dashboard, or `vdpi uninstall` to remove all files and restore OS network settings.

---

## Documentation

| Guide | Contents |
| :--- | :--- |
| [Engine Modes (TUN vs Proxy)](docs/engines.md) | Platform TUN architecture, Proxy OS integration, 7-stage adaptive TLS engine |
| [VPN Coexistence & Custom Bypass](docs/vpn-and-bypass.md) | `VpnGuard` auto-yield, Tailscale/Docker/LAN safety, `--bypass` & `--include` rules |
| [CLI & config.toml Reference](docs/cli.md) | All commands, global flags, precedence rules, and full `config.toml` schema |
| [Diagnostics & Troubleshooting](docs/diagnostics.md) | `vdpi status`, `vdpi doctor`, Defender/antivirus notes, recovery steps |
| [Building from Source](docs/building.md) | Workspace crate layout and build steps for Desktop, Android APK, and iOS IPA |

---

## License

Released under the [MIT License](./LICENSE) · [Changelog](./CHANGELOG.md) · [Security](./SECURITY.md) · Official repository: [github.com/Vuln-Inc/vdpi](https://github.com/Vuln-Inc/vdpi) · Copyright (c) 2026 [Vuln-Inc](https://github.com/Vuln-Inc).  
Official Windows release archives bundle the unmodified WHQL-signed Wintun `0.14.1` driver (`wintun.dll` and `WINTUN-LICENSE.txt`, Copyright (C) WireGuard LLC, distributed under the Wintun / GPLv2 license - see [wintun.net](https://www.wintun.net/)).
