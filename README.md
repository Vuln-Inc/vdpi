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
| **7-Stage Adaptive Auto-Heal** | Automatically escalates across multi-record TLS splitting, TCP `MSG_OOB` SNI & TLS-framing desync, and 12+ record storms — learning the winning strategy per host and ISP network. |
| **Full App, Voice & Game Support** | Protocol-autodetecting **HTTP/1.1 + HTTPS `CONNECT` + SOCKS5 (`CONNECT` & `UDP ASSOCIATE`) + SOCKS4a** proxy with native OS proxy and environment bridging. |
| **Anti-Poisoning DNS Ring** | In-memory TTL-cached **RFC 8484 DoH** with sticky healthy failover across 4 independent networks (`1.1.1.1`, `8.8.8.8`, `94.140.14.140`, `9.9.9.9`), non-port-53 UDP fallback (`1253`, `443`, `5353`), and sinkhole IP filtering. |
| **100% VPN Coexistence** | Pure userspace proxy (no WinDivert, kernel extensions, or fake-TTL injection) — coexists seamlessly with WireGuard, Cloudflare WARP, OpenVPN, Mullvad, and ProtonVPN. |
| **Smart Local & Portal Bypass** | Automatically bypasses LAN/private subnets (`localhost`, `10.0.0.0/8`, `192.168.0.0/16`, `*.local`), government/banking portals, and any custom `--bypass` rules. |

### Adaptive 7-Stage TLS Engine

Every outbound TLS handshake validates the upstream `ServerHello` (`0x16 0x03`) — rejecting TCP resets, TLS Alerts (`0x15`), and injected ISP block pages — and automatically escalates, caches, and self-heals across networks:

| Stage | Strategy | How It Works |
| :---: | :--- | :--- |
| **1** | `ComboMultiRecord` | Splits the TLS `ClientHello` into 4 wire-paced RFC-compliant `0x16` records across the handshake header and SNI midpoint (defeating OS TCP coalescing and shallow DPI). |
| **2** | `OobSniDesync` | Injects 1 TCP Out-of-Band (`MSG_OOB`, `URG=1`) decoy byte right at the SNI midpoint. Server TCP stacks (`SO_OOBINLINE=0`) strip the urgent byte seamlessly while full-stream-reassembling stateful DPI boxes see a corrupted hostname and pass the connection through. |
| **3** | `MultiRecordOob` | Combines 4-record TLS splitting with a `MSG_OOB` urgent decoy byte at the TLS record boundary inside SNI, shifting subsequent TLS record framing for stateful DPI state machines. |
| **4** | `FineFragment` | Keeps a single intact outer TLS record split across 4 wire-paced TCP segments (for strict servers or firewalls that reject multi-record `ClientHello`s or strip `URG`). |
| **5** | `DeepRecordStorm` | Emits 12+ wire-paced `0x16` records (10 tiny 2-byte lead records exhausting hardware DPI per-flow packet caps before the SNI even hits the wire, followed by SNI-split records) and auto-promotes globally on strict stateful ISPs. |
| **6** | `SlowSniSlice` | Single intact outer TLS record with 2-byte paced SNI slicing and a 20ms midpoint gap for strict servers behind stateful burst-reassembling DPI. |
| **7** | `DirectPassthrough` | Falls back cleanly to an unmodified handshake for unblocked strict WAFs and caches the winning strategy per hostname. |

---

## Installation

### First launch

Open `vdpi.exe` from File Explorer, or run `vdpi` with no arguments in an interactive terminal. Choose **Run directly** to use vdpi immediately, **Install for automatic startup** to register a background service, or **Quit** to leave without starting. Linux desktop launches use Zenity when available.

**Run directly** saves your choice for future launches and prints a reminder that you can install later with `vdpi install`. Use `vdpi launcher` to reopen the chooser, or `vdpi start` to skip it. Commands with explicit flags and unattended shell invocations can start the foreground proxy without a prompt.

The run-only preference is a file named `run-directly` in `%LOCALAPPDATA%\vdpi` on Windows, `~/Library/Application Support/vdpi` on macOS, or `$XDG_CONFIG_HOME/vdpi` (default `~/.config/vdpi`) on Linux.

On Windows, foreground vdpi restores the previous system proxy when its console closes. Foreground mode does not export user proxy environment variables, because apps launched while vdpi is running could keep those variables after it exits. An installed background service runs independently of the console window.

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
| **Active Inline & Stateful Stream-Reassembling DPI** | 7-Stage wire-paced adaptive TLS engine (`ComboMultiRecord` -> `OobSniDesync` -> `MultiRecordOob` -> `FineFragment` -> `DeepRecordStorm` -> `SlowSniSlice`) with automatic ISP-wide promotion |
| **Transparent Port-53 DNS Hijacking & Poisoning** | Sticky multi-ASN IP-literal RFC 8484 DoH ring with concurrent failover + 30s circuit-breaker to non-port-53 UDP (`1253`, `443`, `5353`) + sinkhole IP rejection |
| **SNI, HTTP `Host`, IPv6 CNAME & QUIC Filtering** | CNAME-safe IPv4/IPv6 resolution, 3-segment wire-paced HTTP `Host` splitting, and clean TCP TLS fallback for QUIC-throttled networks |
| **Strict CDNs, Banking & Government Portals** | Built-in LAN/government/banking bypass policy (`--bypass` extensible) + Stage 7 Auto-Heal Passthrough |

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

Use the current stable Rust toolchain:

```bash
git clone https://github.com/Vuln-Inc/vdpi.git
cd vdpi
cargo build --locked --release
cargo test --locked
./target/release/vdpi install
```

The proxy allows up to 256 concurrent client sessions across both listeners. At capacity,
new connections are closed until a slot becomes free. Incomplete HTTP headers and SOCKS
negotiations time out after 15 seconds once the protocol is detected. Established tunnels
are not affected by the negotiation timeout.

The normal test suite uses local sockets. To also run the optional public DNS smoke test,
use `cargo test --locked resolves_discord_and_roblox_via_live_doh -- --ignored`.

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
│   ├── desync.rs               # 7-stage adaptive OOB, multi-record, and paced SNI DPI desynchronizer
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
