# Desktop Engines: TUN Mode, Proxy Mode, and Adaptive TLS Desync

`vdpi` provides two desktop transport engines sharing the same Rust 7-stage adaptive TLS desync engine and anti-poisoning RFC 8484 DoH ring:

- **TUN Mode** creates a local Layer 3 virtual network adapter (`Wintun`, `utun`, or `/dev/net/tun`) and routes public internet traffic through `vdpi` transparently. Every application works automatically without system proxy settings or environment variables.
- **Proxy Mode** runs a local HTTP/HTTPS/SOCKS5/SOCKS4a proxy (`127.0.0.1:8080` and `127.0.0.1:1080`) and configures OS proxy settings. It requires no virtual network adapter and works unprivileged on macOS and Linux (and in foreground mode on Windows).

---

## TUN Mode vs Proxy Mode

| Capability | TUN Mode | Proxy Mode |
| :--- | :--- | :--- |
| **Traffic capture** | Layer 3 virtual NIC (`Wintun` / `utun` / `/dev/net/tun`) + userspace TCP/UDP stack (`netstack-smoltcp`) | Local loopback listeners (`127.0.0.1:8080` HTTP/HTTPS/SOCKS5/4a + `127.0.0.1:1080` SOCKS5 TCP/UDP) |
| **Application coverage** | System-wide: browsers, Discord, Roblox, Electron, games, CLI tools, `libcurl`, and apps that ignore OS proxies | Apps honoring WinINET / WinHTTP / `networksetup` / GNOME / KDE or `HTTP_PROXY` / `HTTPS_PROXY` |
| **OS proxy / env changes** | None (zero `HTTP_PROXY`, `HTTPS_PROXY`, WinINET, or WinHTTP edits) | Configures OS proxy settings and user environment variables |
| **Browser restart on install** | Not required | Open browsers must restart once so child processes inherit `HTTPS_PROXY` |
| **Privileges required** | Windows Administrator (service) / macOS root (`LaunchDaemon`) / Linux `CAP_NET_ADMIN` | Windows Service (Admin) or unprivileged foreground; unprivileged on macOS (`LaunchAgent`) and Linux (`systemd --user`) |
| **Memory footprint** | ~16-22 MB RAM (`TunProfile::DESKTOP`) | ~8-14 MB RAM |
| **DNS protection** | Intercepts UDP/53 and TCP/53 at the virtual interface via DoH ring | Resolves hostnames inside the proxy via DoH ring |
| **QUIC handling** | Drops UDP/443 QUIC for desync-eligible hosts with ICMP reject for instant TCP/TLS fallback | Drops UDP/443 QUIC over SOCKS5 UDP relay (unless `--allow-quic`) |
| **VPN coexistence** | `VpnGuard` 0ms auto-yield on full-tunnel VPN; split overlays (Tailscale mesh, Docker, WSL) work untouched | Pure userspace proxy; yields/skips proxy override when full-tunnel VPN holds default route |
| **Anticheat compatibility** | Safe (WHQL-signed Wintun / native OS TUN; no kernel packet hooking) | Safe (pure userspace loopback proxy) |

---

## TUN Mode Architecture by Platform

All desktop TUN backends share `vdpi-tun` with `TunProfile::DESKTOP` (MTU `1500`, up to `256` concurrent TCP sessions, `512` Cone-NAT UDP flows, `128` inflight DNS queries, `64 KB` TCP receive / `128 KB` TCP send buffers, `1 MB` UDP socket buffers, and ICMP-backed QUIC rejection for immediate HTTP/2 TCP fallback).

To prevent routing loops, every outbound socket opened by `vdpi` (TCP upstream, UDP Cone-NAT relay, UDP DNS, and DoH) is bound directly to the physical uplink through `DynamicOutboundBinder` before `connect()` or `bind()`. When you switch between Wi-Fi and Ethernet, the binder hot-swaps the active physical interface without restarting `vdpi`.

### Windows

- **WHQL-signed Wintun `0.14.1`:** `vdpi-windows-x86_64.zip` ships the pinned, official WireGuard LLC WHQL-signed `wintun.dll` (`0.14.1`) and `WINTUN-LICENSE.txt` alongside `vdpi.exe`. Release CI verifies the archive SHA-256, `wintun.dll` SHA-256, and `WireGuard LLC` Authenticode signature on every build.
- **51-CIDR crash-proof routing:** Instead of installing a single `0.0.0.0/0` default route that can shadow local networks or leave connectivity stranded on failure, `vdpi` routes public unicast IPv4 space using 51 non-overlapping public IPv4 complement CIDRs attached directly to the Wintun interface LUID. Private LANs, loopback, link-local, CGNAT/Tailscale, Docker/WSL bridges, and multicast stay on native kernel routes. Because all 51 routes are owned by the Wintun adapter object, Windows automatically removes them the instant the adapter handle closes on normal exit, service stop, or crash.
- **Uplink socket binding (`IP_UNICAST_IF`):** Outbound IPv4 sockets use `IP_UNICAST_IF` (network byte order, `htonl(if_index)`) and IPv6 sockets use `IPV6_UNICAST_IF` (host byte order) to exit directly through the physical NIC. If no physical uplink is available, sockets fail closed with `WSAENETUNREACH` instead of looping into Wintun.
- **Zero `HTTP_PROXY` or browser restart bugs:** TUN mode never writes WinINET registry keys, WinHTTP rules, or `HKCU\Environment` variables. Browsers, Electron apps, `libcurl` clients (such as `RobloxPlayerBeta.exe`), and CLI tools work immediately without restarting open windows.
- **UDP fast-path & footprint:** Runs at ~16-22 MB RAM with Windows `SIO_UDP_CONNRESET` handling on Cone-NAT UDP sockets so unreachable peers never tear down voice or game relays.
- **Anticheat safety:** Wintun is a standard WHQL-signed Layer 3 virtual network adapter (the same driver used by WireGuard, Tailscale, and Mullvad). Unlike WinDivert or kernel-level packet injection drivers, it does not hook kernel network stacks or forge raw packets, so kernel anticheats (Vanguard, Easy Anti-Cheat, BattlEye) treat it as a normal network interface.

### macOS

- **Native kernel `utun`:** Opens macOS's built-in `utun` virtual interface via `PF_SYSTEM` / `SYSPROTO_CONTROL` with zero kernel extensions (kexts) or third-party drivers.
- **Uplink socket binding (`IP_BOUND_IF`):** Binds outbound sockets directly to the physical interface index (for example `en0`) using `IP_BOUND_IF` (`IPPROTO_IP`, option `25`) for IPv4 and `IPV6_BOUND_IF` (`IPPROTO_IPV6`, option `125`) for IPv6, dynamically following Wi-Fi/Ethernet transitions.
- **`LaunchDaemon` vs `LaunchAgent`:**
  - **TUN mode** requires root privileges to create `utun` interfaces, install routes, and manage DNS, so `vdpi install --tun` registers a system `LaunchDaemon` (`/Library/LaunchDaemons/com.vdpi.daemon.plist`).
  - **Proxy mode** runs unprivileged as a per-user `LaunchAgent` (`~/Library/LaunchAgents/com.vdpi.plist`).
- **Snapshot-backed DNS & crash-cleanup guard:** On TUN startup, `vdpi` snapshots each active physical network service's DNS configuration via `networksetup -getdnsservers` (preserving DHCP/automatic vs custom servers), points service DNS to the virtual DNS endpoint (`198.18.0.2`), installs LAN exclusion routes and split default routes (`0.0.0.0/1`, `128.0.0.0/1`), persists the rollback state, and spawns a detached `setsid()` crash-cleanup guard (`--internal-macos-tun-guard`). On normal exit, `SIGKILL`, crash, or post-crash recovery from persistent state, `vdpi` and `--internal-macos-tun-guard` delete the managed routes in reverse order and restore the original DNS servers via `networksetup -setdnsservers`.

### Linux

- **Native `/dev/net/tun`:** Uses the standard Linux kernel TUN character device with no out-of-tree modules.
- **Policy routing (`SO_MARK 0x5644`):** Every outbound socket opened by `vdpi` is tagged with `SO_MARK` fwmark `0x5644` (ASCII `"VD"`). Policy routing rules (`ip rule`) direct locally originated (`iif lo`) default-route traffic into routing table `202` (`vdpi0`) while routing `0x5644`-marked packets through the physical `main` routing table (with a fail-closed unreachable guard and `suppress_prefixlength 0` preserving LAN, Docker, and split-tunnel routes).
- **`CAP_NET_ADMIN` privilege model:** TUN mode only needs `CAP_NET_ADMIN` to open `/dev/net/tun` and configure link routes and fwmark rules. It does not require unrestricted root access across the process lifetime (`systemd` service capability bounding or `setcap cap_net_admin+eip`).
- **3-backend DNS management & `ExecStopPost` cleanup:** When `systemd-resolved` is active, DNS settings are attached directly to the `vdpi0` link and withdraw automatically when the `/dev/net/tun` descriptor closes. On systems without `systemd-resolved`, `vdpi` falls back to an ephemeral **NetworkManager** drop-in (`/run/NetworkManager/conf.d/99-vdpi-dns.conf`) or a marker-guarded `/etc/resolv.conf` (`# Managed by vdpi TUN mode`) backed up under `/var/lib/vdpi/` (restored only if the marker is still present so external edits are never clobbered). The installed `systemd` system unit (`/etc/systemd/system/vdpi.service`) also configures `ExecStopPost=+/usr/local/bin/vdpi --internal-linux-tun-cleanup` to remove `ip rule` policy rules, table `202` routes, and DNS state even after an abrupt crash or `SIGKILL`.

---

## Switching Between TUN and Proxy Modes

The active desktop engine is persisted as `engine = "tun"` or `engine = "proxy"` in `config.toml` (inspect or manage with `vdpi config`).

### CLI Commands

```sh
# Switch an installed background service (and config.toml) to TUN mode
vdpi engine tun

# Switch an installed background service (and config.toml) to Proxy mode
vdpi engine proxy

# Install the background service explicitly in TUN or Proxy mode
vdpi install --tun
vdpi install --proxy

# Run in the foreground for the current session in a specific mode
# (does not overwrite the installed background service mode)
vdpi start --tun
vdpi start --proxy
```

Switching with `vdpi engine tun` or `vdpi engine proxy` handles cleanup automatically:

- Moving **Proxy -> TUN** disables OS proxy settings (`WinINET` / `WinHTTP` / `networksetup` / GNOME / KDE / env vars) and migrates the background service (for example, `LaunchAgent` -> `LaunchDaemon` on macOS).
- Moving **TUN -> Proxy** tears down the virtual adapter, routes, and TUN DNS state, migrates back to the Proxy service, and re-applies system proxy settings.

### Control Center (`[2]`)

Run `vdpi` (or `vdpi launcher`) to open the interactive `ratatui` Control Center:

- Press **`2`** (or select menu item **`[2]`**) to toggle between **TUN Mode** and **Proxy Mode**.
- The live status panel at the top immediately reflects the active engine, service state, physical uplink / proxy listeners, and Anti-DPI telemetry.

---

## Proxy Mode Architecture

Proxy mode runs a single-process userspace server with up to 256 concurrent client sessions (15-second handshake negotiation timeout):

- **Primary listener (`127.0.0.1:8080`, `-p`):** Protocol-autodetecting listener handling HTTP/1.1, HTTPS `CONNECT`, SOCKS5, and SOCKS4a.
- **Dedicated SOCKS5 listener (`127.0.0.1:1080`, `-s`, set `0` to disable):** Supports both TCP `CONNECT` and UDP `ASSOCIATE`.

### OS Proxy Integration

| Platform | Mechanisms Configured | Foreground Cleanup |
| :--- | :--- | :--- |
| **Windows** | **WinINET** (`HKCU` or active interactive `HKU\<SID>` hives + `WTS_SESSION_LOGON` / `WTS_SESSION_UNLOCK` instant reconciliation), **`HKCU\Environment`** (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` broadcast via `WM_SETTINGCHANGE`), and **WinHTTP** (`netsh winhttp set proxy` in service mode when no unrelated external proxy is configured) | Detached lease guard process (`--internal-foreground-proxy-guard`) restores WinINET and `HKCU\Environment` automatically even if the console window is force-closed |
| **macOS** | `networksetup` (HTTP, HTTPS, and SOCKS5 on physical interfaces, skipping VPN/bridge services) + `launchctl setenv` (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`) | Restores only `vdpi`-owned proxy entries on exit |
| **Linux** | GNOME `gsettings` (`org.gnome.system.proxy`) + KDE `kioslaverc` + `systemctl --user set-environment` | Restores only `vdpi`-owned proxy entries on exit |

Pass `--no-system-proxy`, `--no-socks-proxy`, or `--no-env-proxy` to selectively opt out of OS proxy configuration while keeping the local listeners active.

### Seamless Windows Service Updates (`SERVICE_CONTROL_UPGRADE_STOP`)

When you run `vdpi update` while Windows Proxy Mode is installed as a background service, the updater sends a custom `SERVICE_CONTROL_UPGRADE_STOP` control code instead of a standard `SERVICE_CONTROL_STOP`:

- On `SERVICE_CONTROL_UPGRADE_STOP`, the outgoing service stops accepting connections and exits **without** wiping WinINET, WinHTTP, or `HKCU\Environment` proxy entries.
- The updater swaps `%ProgramFiles%\vdpi\bin\vdpi.exe` (after SHA-256 verification) and starts the new service immediately.
- Active browsers and desktop apps avoid a proxy configuration flap during the brief binary handoff.
- Normal `vdpi pause`, `vdpi stop`, and `vdpi uninstall` still issue standard `SERVICE_CONTROL_STOP` and remove all proxy settings cleanly.

### Restarting Open Browsers Once on First Proxy Install

On Windows and macOS, processes inherit environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`) only at process launch:

- Browsers (Chrome, Edge) use WinINET / `networksetup` immediately, so normal browsing works without restarting.
- Native game clients and `libcurl`-based apps (such as `RobloxPlayerBeta.exe`) ignore WinINET and rely on `HTTPS_PROXY`. If a browser was **already open** before your first `vdpi install --proxy` or `vdpi start --proxy`, restart that browser **once** so child apps launched via protocol handlers (`roblox-player://`) inherit `HTTPS_PROXY`.
- Once installed as a background service, `HTTPS_PROXY` is present from login on every subsequent boot. Switching to **TUN mode** removes this requirement entirely.

---

## Adaptive 7-Stage TLS Desync Engine

Both TUN mode and Proxy mode (as well as Android and iOS) execute the same adaptive TLS desync engine in `vdpi-core`.

For every outbound TLS connection to a non-bypassed host, `vdpi` validates the upstream `ServerHello` (`0x16 0x03`). If the connection encounters a TCP reset (`RST`), premature EOF, handshake timeout, TLS Alert (`0x15`), or an injected non-TLS ISP block page (such as an HTTP `302`/`403` redirect), `vdpi` automatically escalates to the next stage without dropping the client session:

| Stage | Strategy | Mechanism |
| :---: | :--- | :--- |
| **1** | `ComboMultiRecord` | Splits the TLS `ClientHello` into 4 wire-paced RFC-compliant `0x16` records across the handshake header and SNI midpoint (defeats OS TCP coalescing and shallow DPI). |
| **2** | `OobSniDesync` | Injects 1 TCP Out-of-Band (`MSG_OOB`, `URG=1`) decoy byte at the SNI midpoint. Real server TCP stacks (`SO_OOBINLINE=0`) strip the urgent byte cleanly while stateful DPI boxes see a corrupted hostname and pass the flow through. |
| **3** | `MultiRecordOob` | Combines 4-record TLS splitting with a `MSG_OOB` urgent decoy byte at the TLS record boundary inside SNI, shifting subsequent TLS record framing for stateful DPI state machines. |
| **4** | `FineFragment` | Keeps a single intact outer TLS record split across 4 wire-paced TCP segments (for strict servers or firewalls that reject multi-record `ClientHello`s or strip `URG`). |
| **5** | `DeepRecordStorm` | Emits 12+ wire-paced `0x16` records (up to 10 tiny 2-byte lead records exhausting hardware DPI per-flow packet caps before SNI hits the wire, followed by SNI-split records). |
| **6** | `SlowSniSlice` | Single intact outer TLS record with 2-byte paced SNI slicing and a 20ms midpoint gap for strict servers behind stateful burst-reassembling DPI. |
| **7** | `DirectPassthrough` | Falls back cleanly to an unmodified single-write handshake for unblocked strict WAFs/CDNs and caches the winning strategy per host. |

For plaintext HTTP/1.1 requests, `vdpi` applies 3-segment wire-paced `Host` header splitting.

### Global ISP Stage Promotion

When an earlier desync stage fails due to a network block (TCP reset, timeout, or non-TLS injected block page) rather than a server TLS Alert, and a later desync stage (Stages 2-6) succeeds, `vdpi` can promote that winning desync stage as `preferred_isp_stage` so subsequent new hosts skip known-blocked stages on first connect. Promotion hygiene prevents isolated single-host anomalies from over-promoting the global stage, and Stage 7 (`DirectPassthrough`) is strictly per-host and never promoted globally.

### Persistent Stage Cache (`adaptive-cache.json`)

Learned per-host winning strategies and the promoted `global_isp_stage` are persisted to `adaptive-cache.json` so restarts and network reconnects reuse working strategies immediately without re-escalating.

- **Format:** Versioned JSON (`version: 1`) containing `global_isp_stage` and `entries` (`{ "host", "stage", "updated_at" }`).
- **Limits & durability:** Bounded to **256 hosts** (oldest evicted first), **7-day TTL** per entry, **512 KB** read cap, **10-second** write debounce, and atomic temp-file + rename writes (with rollback backup on Windows).
- **Self-healing:** If all stages fail for a cached host (for example after changing ISPs), the stale entry is evicted automatically so the next attempt probes fresh.
- **Manual reset:** Press `c` in the foreground dashboard (`vdpi start`), or delete the file below and restart the service.

| Platform | Default `adaptive-cache.json` Path |
| :--- | :--- |
| **Windows** | `%LOCALAPPDATA%\vdpi\adaptive-cache.json` |
| **macOS** | `~/Library/Caches/vdpi/adaptive-cache.json` |
| **Linux** | `$XDG_CACHE_HOME/vdpi/adaptive-cache.json` (fallback: `~/.cache/vdpi/adaptive-cache.json`) |
| **Android / iOS** | Managed automatically inside the app cache / iOS App Group container |
