<div align="center">

# `vdpi`

**High-performance, self-healing anti-DPI engine in pure Rust.**

[![Release](https://img.shields.io/github/v/release/Vuln-Inc/vdpi?style=for-the-badge&logo=github&color=38bdf8)](https://github.com/Vuln-Inc/vdpi/releases/latest)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-818cf8?style=for-the-badge)](#installation)
[![Rust](https://img.shields.io/badge/Rust-2021%20Edition-c084fc?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-34d399?style=for-the-badge)](./LICENSE)

Single self-contained binary. Zero scripts. Zero kernel `.sys` drivers.  
Works across ISPs and networks worldwide with instant startup, zero ping penalty, full **Discord** & **Roblox** support, and 100% VPN coexistence.

[Features](#features) · [Installation](#installation) · [Network Compatibility](#network-compatibility) · [Diagnostics](#diagnostics) · [CLI Reference](#cli-reference)

</div>

---

## Features

| Capability | Details |
| :--- | :--- |
| **Single-Binary Self-Installer** | `vdpi install` and `vdpi uninstall` detect your OS automatically — no external `.bat` or `.sh` scripts required. |
| **Native OS Background Services** | Installs as a native **Windows Service (`AUTO_START`)**, **macOS `LaunchAgent`**, or **Linux `systemd --user`** unit. |
| **3-Stage Adaptive Auto-Heal** | Automatically adapts per hostname on TLS handshake alerts or resets so strict CDNs and media never break. |
| **Full App, Voice & Game Support** | Protocol-autodetecting **HTTP/1.1 + HTTPS `CONNECT` + SOCKS5 (`CONNECT` & `UDP ASSOCIATE`) + SOCKS4a** proxy with native OS proxy and environment bridging. |
| **Anti-Poisoning DNS Ring** | In-memory TTL-cached **RFC 8484 DoH** over IP-literal resolvers (`1.1.1.1`, `1.0.0.1`, `8.8.8.8`, `8.8.4.4`, `9.9.9.9`) with port `1253` UDP fallback. |
| **100% VPN Coexistence** | Pure userspace proxy (no WinDivert, kernel extensions, or fake-TTL injection) — coexists seamlessly with WireGuard, Cloudflare WARP, OpenVPN, Mullvad, and ProtonVPN. |
| **Smart Local & Portal Bypass** | Automatically bypasses LAN/private subnets (`localhost`, `10.0.0.0/8`, `192.168.0.0/16`, `*.local`), government/banking portals, and any custom `--bypass` rules. |

### Adaptive 3-Stage TLS Engine

Every outbound TLS handshake is inspected and self-healed automatically if an upstream CDN or server rejects fragmented records:

| Stage | Strategy | How It Works |
| :---: | :--- | :--- |
| **1** | `Combo` | Splits the TLS `ClientHello` into two RFC-compliant `0x16` records at the exact midpoint of the SNI hostname and transmits the pre-SNI record in fine `TCP_NODELAY` segments. |
| **2** | `FineFragment` | If a strict server replies with a TLS Alert (`0x15`) or resets the connection, `vdpi` intercepts the failure before it reaches the client and retries on a fresh socket using single-record 2-byte SNI slicing. |
| **3** | `DirectPassthrough` | If a CDN or WAF requires an unmodified handshake, `vdpi` falls back cleanly to direct passthrough and caches the winning strategy per hostname in memory. |

---

## Installation

Download the release archive for your OS from **[Releases](https://github.com/Vuln-Inc/vdpi/releases/latest)**, extract it, and run `vdpi install`.  
Everything — binary installation, `PATH` registration, background service setup, and OS proxy configuration — is handled natively by `vdpi` itself.

### Windows (Windows 10 & 11 x64)

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
| **Windows** | `%ProgramFiles%\vdpi\bin\vdpi.exe` (added to System `PATH`) | Native Windows Service (`vdpi`, `AUTO_START`, `Tcpip` dependency, crash auto-restart) | Interactive `HKU` / `HKCU` WinINET Registry + `InternetSetOptionW` + `WM_SETTINGCHANGE` + `WTS_SESSION_LOGON` instant sync |
| **macOS** | `~/.vdpi/bin/vdpi` (ad-hoc `codesign`, added to shell `PATH`) | `~/Library/LaunchAgents/com.vdpi.plist` (`RunAtLoad` + `KeepAlive`) | `networksetup` (Wi-Fi / Ethernet, VPN-safe) + `launchctl setenv` |
| **Linux** | `~/.vdpi/bin/vdpi` (static `musl`, symlinked to `~/.local/bin/vdpi`) | `~/.config/systemd/user/vdpi.service` (`systemctl --user`) | GNOME `gsettings` + KDE `kioslaverc` + `systemctl --user set-environment` |

---

## Network Compatibility

`vdpi` is engineered to work on **any ISP, carrier, fiber, cable, or mobile network worldwide** without region-specific configs or manual DNS changes:

| DPI / Censorship Mechanism | Automatic `vdpi` Countermeasure |
| :--- | :--- |
| **Active Inline DPI & TCP Reset Injection** | 3-Stage Adaptive TLS SNI Record Split (`Combo`) + 2-byte single-record `FineFragment` with `TCP_NODELAY` |
| **Transparent Port-53 DNS Hijacking & Poisoning** | Multi-provider IP-literal RFC 8484 DoH ring (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`) with automatic port `1253` UDP fallback |
| **SNI, HTTP `Host`, IPv6 CNAME & QUIC Filtering** | CNAME-safe IPv4/IPv6 resolution, HTTP `Host` midpoint segmentation, and clean TCP TLS fallback for QUIC-throttled networks |
| **Strict CDNs, Banking & Government Portals** | Built-in LAN/government/banking bypass policy (`--bypass` extensible) + Stage 3 Auto-Heal Passthrough |

---

## Diagnostics

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
  start      Start the vdpi engine in the foreground (default when no subcommand is given) [aliases: run]
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

Requires Rust `1.78+`:

```bash
git clone https://github.com/Vuln-Inc/vdpi.git
cd vdpi
cargo build --release
cargo test
./target/release/vdpi install
```

<details>
<summary>Repository layout</summary>

```text
vdpi/
├── Cargo.toml                  # Crate manifest and dependencies
├── LICENSE                     # MIT License
├── README.md                   # Documentation and installation guide
├── src/
│   ├── main.rs                 # CLI entrypoint, Windows SCM dispatch, and signal handling
│   ├── config.rs               # CLI flags, desync modes, and runtime configuration
│   ├── tls.rs                  # Zero-panic TLS ClientHello SNI parser and record splitter
│   ├── bypass.rs               # LAN, private subnet, regex, and portal bypass policy
│   ├── dns.rs                  # Multi-tier RFC 8484 DoH + port-1253 anti-poisoning DNS resolver
│   ├── desync.rs               # 3-stage adaptive auto-heal TLS and HTTP DPI desynchronizer
│   ├── server.rs               # Protocol-autodetecting TCP listener and dual-port SOCKS5 server
│   ├── service.rs              # Cross-platform self-installer, service manager, status, and doctor
│   ├── platform/
│   │   ├── mod.rs              # Cross-platform OS proxy and service abstraction
│   │   ├── windows.rs          # Windows WinINET HKU/HKCU proxy, System PATH, and broadcasts
│   │   ├── windows_service.rs  # Native Windows SCM service dispatcher, UAC elevation, and session sync
│   │   ├── macos.rs            # macOS SystemConfiguration, launchd env, and VPN-aware watchdog
│   │   └── linux.rs            # Linux systemd --user, GNOME gsettings, and KDE kioslaverc
│   └── proxy/
│       ├── mod.rs              # Proxy protocol dispatch
│       ├── http.rs             # HTTP/1.1 forward proxy, HTTPS CONNECT tunnel, and health probe
│       └── socks.rs            # RFC 1928 SOCKS5 (CONNECT + UDP ASSOCIATE) and SOCKS4a server
└── tests/
    └── integration_test.rs     # End-to-end TLS desync, auto-heal, SOCKS5/4a, and UDP relay tests
```

</details>

---

## License

Released under the [MIT License](./LICENSE). Copyright © 2026 [Vuln-Inc](https://github.com/Vuln-Inc).
