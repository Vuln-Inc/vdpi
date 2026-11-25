<div align="center">

# `vdpi`

Self-healing anti-DPI engine in Rust, native across Windows, macOS, Linux, Android, and iOS.  
Runs as a transparent system-wide TUN adapter or a lightweight local proxy with zero remote servers and zero telemetry.

[![Release](https://img.shields.io/github/v/release/Vuln-Inc/vdpi?style=for-the-badge&logo=github&color=38bdf8)](https://github.com/Vuln-Inc/vdpi/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-34d399?style=for-the-badge)](./LICENSE)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20Android%20%7C%20iOS-818cf8?style=for-the-badge)](#quick-install)

[Quick Install](#quick-install) · [Engines](#choosing-an-engine-proxy-vs-tun) · [Getting Started](#getting-started) · [Docs](#documentation) · [Releases](https://github.com/Vuln-Inc/vdpi/releases/latest) · [Changelog](./CHANGELOG.md) · [Security](./SECURITY.md)

</div>

---

## Highlights

<table>
  <tr>
    <td valign="top" width="50%">
      <strong>Two desktop engines (TUN + Proxy)</strong><br>
      Transparent system-wide TUN (<code>Wintun</code> / <code>utun</code> / <code>/dev/net/tun</code>, zero proxy env edits or browser restarts) or classic lightweight local HTTP/SOCKS5 proxy (no virtual adapter, portable) - 1-press switchable.
    </td>
    <td valign="top" width="50%">
      <strong>Native across all 5 platforms</strong><br>
      Single self-contained binary on Windows, macOS, and Linux, plus zero-root local VPN apps for Android (APK) and iOS/iPadOS (IPA) sharing the same Rust core.
    </td>
  </tr>
  <tr>
    <td valign="top" width="50%">
      <strong>Zero-hassle &amp; lightweight</strong><br>
      Self-healing 7-stage adaptive TLS desync engine, anti-poisoning RFC 8484 DoH ring, UDP/443 QUIC blocking, ~10-20 MB RAM, and crash-proof OS teardown.
    </td>
    <td valign="top" width="50%">
      <strong>VPN &amp; gaming safe</strong><br>
      Auto-yields to Mullvad, WireGuard, OpenVPN, ProtonVPN, and WARP and auto-resumes; coexists with Tailscale, Docker, and LAN; WHQL-signed Wintun (anticheat safe) and low-latency UDP NAT for Discord, Roblox, and games.
    </td>
  </tr>
  <tr>
    <td valign="top" width="50%">
      <strong>Control Center TUI</strong><br>
      Interactive <code>ratatui</code> launcher and live throughput sparkline dashboard (<code>vdpi</code>), SHA-256-verified self-updater (<code>vdpi update</code>), and <code>config.toml</code> persistence.
    </td>
    <td valign="top" width="50%">
      <strong>Local-only &amp; verifiable</strong><br>
      All traffic stays on-device with no remote relay servers or analytics. Every release asset is verified against <code>SHA256SUMS.txt</code> (see <a href="./SECURITY.md#binary-verification">SECURITY.md</a>).
    </td>
  </tr>
</table>

---

## Quick Install

### Windows (`x86_64`, Windows 10 & 11)

```powershell
# PowerShell one-liner (SHA-256 verified)
irm https://vuln-inc.github.io/vdpi/install.ps1 | iex

# Scoop (direct manifest, no extra bucket required)
scoop install https://vuln-inc.github.io/vdpi/vdpi.json

# WinGet
winget install Vuln-Inc.vdpi

# Cargo (https://crates.io/crates/vdpi)
cargo install vdpi
```

Direct download: [`vdpi-windows-x86_64.zip`](https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi-windows-x86_64.zip) (bundles pinned WHQL-signed `wintun.dll`) or [crates.io/crates/vdpi](https://crates.io/crates/vdpi).

### macOS & Linux (`universal` / `x86_64` & `arm64`)

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

## Choosing an Engine (Proxy vs TUN)

**Proxy mode is the default** for zero-hassle stability (no virtual network adapter, no routing table edits, and no elevated privileges required on macOS/Linux). Switch to **TUN mode** whenever you want transparent system-wide coverage for games, Discord voice, Roblox, or apps that ignore OS proxy settings.

| Dimension | Proxy Mode (`--proxy`, **Default**) | TUN Mode (`--tun`) |
| :--- | :--- | :--- |
| **Traffic capture** | Local `127.0.0.1:8080` (HTTP/HTTPS/SOCKS5/4a) + `:1080` (SOCKS5 TCP/UDP) | Layer 3 virtual NIC (`Wintun` / `utun` / `/dev/net/tun`) + userspace stack |
| **App coverage** | Browsers & apps honoring OS proxy settings or `HTTP_PROXY` / `HTTPS_PROXY` | System-wide: browsers, Discord, Roblox, games, CLI, `libcurl`, all apps |
| **OS integration** | Sets OS proxy & env vars; restart already-open browsers once on first run | Zero proxy env edits; no browser restart required |
| **Privileges & memory** | Unprivileged foreground (and macOS/Linux service); ~8-14 MB RAM | Prompts for UAC (Windows) or `sudo` / Touch ID (macOS & Linux); ~16-22 MB RAM |
| **VPN & anticheat** | Pure loopback proxy; no virtual adapter; `VpnGuard` auto-yield | `VpnGuard` 0ms auto-yield; WHQL-signed Wintun (anticheat safe) |

### Switching Modes

Your current mode (`Proxy` or `TUN`) is always shown in the `Engine` row of the `vdpi` Control Center and in the Live Dashboard status bar.

- **Interactive TUI:** Run `vdpi` and pick **Switch to TUN mode** / **Switch to Proxy mode** - `vdpi` automatically prompts for elevation (UAC on Windows, `sudo` password or Touch ID on macOS/Linux) when toggling a system TUN service or launching foreground TUN.
- **CLI:**
  ```bash
  vdpi engine         # Show current engine mode (Proxy or TUN)
  vdpi engine tun     # Switch to transparent system-wide TUN mode
  vdpi engine proxy   # Switch back to default local HTTP/SOCKS5 proxy mode
  vdpi --tun start    # Run a one-off foreground TUN session
  vdpi --proxy start  # Run a one-off foreground Proxy session
  ```

For anti-DPI framing modes (`--mode combo` default with 7-stage self-healing auto-escalation, `tls-record`, `split`, `oob`, `disorder`), see [Engine Modes](docs/engines.md) and [CLI Reference](docs/cli.md).

---

## Getting Started

```bash
vdpi              # Open the interactive Control Center TUI (install, switch engine, live telemetry)
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
