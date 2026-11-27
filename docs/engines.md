# Desktop Engines: TUN Mode, Proxy Mode, and Adaptive TLS Desync

`vdpi` provides two desktop transport engines sharing the same Rust 7-stage adaptive TLS desync engine and anti-poisoning RFC 8484 DoH ring:

- **TUN Mode** creates a local Layer 3 virtual network adapter (`Wintun`, `utun`, or `/dev/net/tun`) and routes public internet traffic through `vdpi` transparently. Every application works automatically without system proxy settings or environment variables.
- **Proxy Mode** runs a local HTTP/HTTPS/SOCKS5/SOCKS4a proxy (`127.0.0.1:8080` and `127.0.0.1:1080`) and configures OS proxy settings. It requires no virtual network adapter and works unprivileged on macOS and Linux (and in foreground mode on Windows).

---

## TUN Mode vs Proxy Mode

| Capability | TUN Mode | Proxy Mode |
| :--- | :--- | :--- |
| **Traffic capture** | Layer 3 virtual NIC (`Wintun` / `utun` / `/dev/net/tun`) + in-tree userspace TCP/UDP stack (`smoltcp` 0.14) | Local loopback listeners (`127.0.0.1:8080` HTTP/HTTPS/SOCKS5/4a + `127.0.0.1:1080` SOCKS5 TCP/UDP) |
| **Application coverage** | System-wide: browsers, Discord, Roblox, Electron, games, CLI tools, `libcurl`, and apps that ignore OS proxies | Apps honoring OS fail-open `/vdpi.pac` auto-config (Windows `AutoConfigURL`, macOS `AutoProxyURL`, Linux GNOME/KDE PAC) or explicit local proxy listeners |
| **OS proxy / env changes** | None (zero `HTTP_PROXY`, `HTTPS_PROXY`, WinINET, or PAC edits) | Windows & macOS: fail-open `/vdpi.pac` only (zero proxy env vars); Linux: GNOME/KDE PAC plus optional `systemd --user` `HTTP_PROXY`/`HTTPS_PROXY` env vars (disabled via `--no-env-proxy`) |
| **Browser restart on install** | Not required | Not required (browsers pick up `/vdpi.pac` dynamically) |
| **Privileges required** | Windows Administrator / UAC (service & foreground) / macOS root (`LaunchDaemon` / `sudo`) / Linux root (`systemd` / `sudo`) or `CAP_NET_ADMIN` | Windows Service (Admin) or unprivileged foreground; unprivileged on macOS (`LaunchAgent`) and Linux (`systemd --user`) |
| **Memory footprint** | ~16-22 MB RAM (`TunProfile::DESKTOP`) | ~8-14 MB RAM |
| **DNS protection** | Intercepts UDP/53 and TCP/53 at the virtual interface via DoH ring | Resolves hostnames inside the proxy via DoH ring |
| **QUIC handling** | Drops UDP/443 QUIC for desync-eligible hosts with ICMP reject for instant TCP/TLS fallback | Drops UDP/443 QUIC over SOCKS5 UDP relay (unless `--allow-quic`) |
| **VPN coexistence** | `VpnGuard` 0ms auto-yield on full-tunnel VPN; split overlays (Tailscale mesh, Docker, WSL) work untouched | Pure userspace proxy; yields/skips proxy override when full-tunnel VPN holds default route |
| **Anticheat compatibility** | Safe (WHQL-signed Wintun / native OS TUN; no kernel packet hooking) | Safe (pure userspace loopback proxy) |

---

## TUN Mode Architecture by Platform

All desktop TUN backends share `vdpi-tun` (built on an in-tree `smoltcp` 0.14 userspace stack) with `TunProfile::DESKTOP` (MTU `16384`, up to `512` concurrent TCP sessions, `512` Cone-NAT UDP flows, `256` inflight DNS queries, `448 KiB` TCP receive/send buffers — sized below Windows NT Heap's 508 KiB `VirtualAlloc` threshold for glitch-free real-time audio, `256 KiB` UDP socket buffers, and ICMP-backed QUIC rejection for immediate HTTP/2 TCP fallback).

To prevent routing loops, every outbound socket opened by `vdpi` (TCP upstream, UDP Cone-NAT relay, UDP DNS, and DoH) is bound directly to the physical uplink through `DynamicOutboundBinder` before `connect()` or `bind()`. When you switch between Wi-Fi and Ethernet, the binder hot-swaps the active physical interface without restarting `vdpi`.

### Windows

- **WHQL-signed Wintun `0.14.1`:** `vdpi-windows-x86_64.zip` ships the pinned, official WireGuard LLC WHQL-signed `wintun.dll` (`0.14.1`) and `WINTUN-LICENSE.txt` alongside `vdpi.exe`. Release CI verifies the archive SHA-256, `wintun.dll` SHA-256, and `WireGuard LLC` Authenticode signature on every build.
- **65-CIDR crash-proof routing:** Instead of installing a single `0.0.0.0/0` default route that can shadow local networks or leave connectivity stranded on failure, `vdpi` routes public unicast IPv4 space using 65 non-overlapping public IPv4 complement CIDRs attached directly to the Wintun interface LUID. Private LANs, loopback, link-local, `192.0.0.0/24` (DS-Lite/IETF), CGNAT/Tailscale, Docker/WSL bridges, and multicast stay on native kernel routes. Because all 65 routes are owned by the Wintun adapter object (and `vdpi` also cleans up phantom/orphaned `vdpi0` nodes via SetupAPI on recovery/pause/uninstall), connectivity stays safe even after an abrupt crash or kill.
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
- **8-CIDR non-zero-anchor routing:** Installs 8 non-overlapping IPv4 split routes (`1.0.0.0/8`, `2.0.0.0/7`, `4.0.0.0/6`, `8.0.0.0/5`, `16.0.0.0/4`, `32.0.0.0/3`, `64.0.0.0/2`, `128.0.0.0/1`) covering `1.0.0.0..=255.255.255.255` while leaving `0.0.0.0/8` untouched so `IP_BOUND_IF` never hits `ENETUNREACH` on modern macOS, paired with `-ifscope` physical default routes and explicit LAN/CGNAT/link-local exclusion routes (`10.0.0.0/8`, `100.64.0.0/10`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `224.0.0.0/4`, `240.0.0.0/4`).
- **Session-scoped `SCDynamicStore` DNS & crash-cleanup guard:** On TUN startup, `vdpi` publishes virtual DNS (`198.18.0.2`, plus `fd00:7664:7069::2` when `--tun-ipv6` is enabled) via native `SCDynamicStore` session keys (`kSCDynamicStoreUseSessionKeys = true`) under `State:/Network/Service/com.vdpi.tun/*`, so macOS automatically reclaims DNS settings when the process exits or crashes without mutating permanent `networksetup` service DNS. Managed route rollback state is persisted to `/Library/Application Support/vdpi/macos-tun-state.json`, and a detached `setsid()` crash-cleanup guard (`--internal-macos-tun-guard`) deletes managed routes in reverse order on abrupt exit or `SIGKILL`.

### Linux

- **Native `/dev/net/tun`:** Uses the standard Linux kernel TUN character device with no out-of-tree modules.
- **Policy routing (`SO_MARK 0x5644`):** Every outbound socket opened by `vdpi` is tagged with `SO_MARK` fwmark `0x5644` (ASCII `"VD"`). Policy routing rules (`ip rule`) direct locally originated (`iif lo`) default-route traffic into routing table `202` (`vdpi0`) while routing `0x5644`-marked packets through the physical `main` routing table (with a fail-closed unreachable guard and `suppress_prefixlength 0` preserving LAN, Docker, and split-tunnel routes).
- **Privilege model (root / `CAP_NET_ADMIN`):** TUN mode requires root privileges (via the `systemd` system unit `/etc/systemd/system/vdpi.service` or `sudo` for foreground sessions) or `CAP_NET_ADMIN` (`setcap cap_net_admin+eip`) to open `/dev/net/tun` and configure link routes and fwmark rules.
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

- Moving **Proxy -> TUN** disables OS fail-open PAC proxy settings (`AutoConfigURL` / `AutoProxyURL` / GNOME & KDE PAC) and migrates the background service (for example, `LaunchAgent` -> `LaunchDaemon` on macOS).
- Moving **TUN -> Proxy** tears down the virtual adapter, routes, and TUN DNS state, migrates back to the Proxy service, and re-applies fail-open `/vdpi.pac` proxy settings.

### Control Center (`[3]` when running)

Run `vdpi` (or `vdpi launcher`) to open the interactive `ratatui` Control Center:

- Press **`3`** (menu item **`[3]`**) when the background service is running (or **`[2]`** when stopped/not installed) to toggle between **TUN Mode** and **Proxy Mode**.
- The live status panel at the top immediately reflects the active engine, service state, physical uplink / proxy listeners, and Anti-DPI telemetry.

---

## Proxy Mode Architecture

Proxy mode runs a single-process userspace server with up to 256 concurrent client sessions (15-second handshake negotiation timeout):

- **Primary listener (`127.0.0.1:8080`, `-p`):** Protocol-autodetecting listener handling HTTP/1.1, HTTPS `CONNECT`, SOCKS5, SOCKS4a, `/vdpi-health`, and `/vdpi.pac`.
- **Dedicated SOCKS5 listener (`127.0.0.1:1080`, `-s`, set `0` to disable):** Supports both TCP `CONNECT` and UDP `ASSOCIATE`.

### OS Proxy Integration (Fail-Open `/vdpi.pac`)

Every desktop platform uses `vdpi`'s local fail-open PAC script (`http://127.0.0.1:<port>/vdpi.pac`), which returns `DIRECT` for localhost, private LAN/CGNAT/IPv6 ULA ranges, and captive-portal probes, and `PROXY 127.0.0.1:<port>; DIRECT` for public traffic. Because the PAC falls back to `DIRECT` whenever the local proxy is unreachable, force-killing or crashing `vdpi` on Windows or macOS never bricks direct internet access. On Windows and macOS, `vdpi` does **not** write fail-closed `HTTP_PROXY`/`HTTPS_PROXY` environment variables or `netsh winhttp` manual proxies (and auto-cleans legacy ones left by older versions); on Linux, `vdpi` configures GNOME/KDE PAC and also exports `systemd --user` `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` unless `--no-env-proxy` (`env_proxy = false`) is set.

| Platform | Mechanisms Configured | Foreground Cleanup |
| :--- | :--- | :--- |
| **Windows** | **WinINET fail-open PAC** (`AutoConfigURL = http://127.0.0.1:<port>/vdpi.pac`, `ProxyEnable = 0`) across `HKCU` or active interactive `HKU\<SID>` hives + `WTS_SESSION_LOGON` / `WTS_SESSION_UNLOCK` reconciliation; auto-cleans legacy `HKCU\Environment` proxy vars and `vdpi`-owned WinHTTP proxies | Detached lease guard process (`--internal-foreground-proxy-guard`) restores prior WinINET state automatically even if the console window is force-closed |
| **macOS** | `networksetup -setautoproxyurl` / `-setautoproxystate on` (`AutoProxyURL = http://127.0.0.1:<port>/vdpi.pac`) on physical network services (skipping VPN/bridge services); auto-cleans legacy loopback `launchctl` env vars | Restores prior `AutoProxyURL` state (or turns off `vdpi` PAC) on exit |
| **Linux** | Fail-open PAC (`http://127.0.0.1:<port>/vdpi.pac`) via GNOME `gsettings` (`org.gnome.system.proxy` `mode='auto'`, `autoconfig-url`) and KDE `kioslaverc` (`ProxyType=2`, `Proxy Config Script`), plus optional `systemd --user` `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` (disable with `--no-env-proxy`) | Restores only `vdpi`-owned PAC and env settings on exit |

Pass `--no-system-proxy` to disable OS PAC integration while keeping the local HTTP/SOCKS5 listeners active.

### Seamless Windows Service Updates (`SERVICE_CONTROL_UPGRADE_STOP`)

When you run `vdpi update` while Windows Proxy Mode is installed as a background service, the updater sends a custom `SERVICE_CONTROL_UPGRADE_STOP` control code instead of a standard `SERVICE_CONTROL_STOP`:

- On `SERVICE_CONTROL_UPGRADE_STOP`, the outgoing service stops accepting connections and exits **without** wiping the WinINET `AutoConfigURL` PAC entry.
- The updater swaps `%ProgramFiles%\vdpi\bin\vdpi.exe` (after SHA-256 verification) and starts the new service immediately.
- Active browsers and desktop apps avoid a proxy configuration flap during the brief binary handoff, and `/vdpi.pac` fails open to `DIRECT` for any request landing in the sub-second restart window.
- Normal `vdpi pause`, `vdpi stop`, and `vdpi uninstall` still issue standard `SERVICE_CONTROL_STOP` and restore prior WinINET settings cleanly.

### Apps Ignoring System PAC (When to Use TUN Mode)

Browsers (Chrome, Edge, Firefox) and Electron apps such as Discord pick up `/vdpi.pac` dynamically with no browser restart required. Native game clients and `libcurl`-based apps that ignore OS PAC auto-config (such as `RobloxPlayerBeta.exe`) are not captured by Proxy mode unless configured to use `127.0.0.1:8080` / `:1080` directly; switch to **TUN mode** (`vdpi engine tun`) for transparent system-wide coverage of all TCP/UDP traffic.

---

## Adaptive 7-Stage TLS Desync Engine

Both TUN mode and Proxy mode (as well as Android and iOS) execute the same adaptive TLS desync engine in `vdpi-core`.

For every outbound TLS connection to a non-bypassed host, `vdpi` validates the upstream `ServerHello` (`0x16 0x03`). If the connection encounters a TCP reset (`RST`), premature EOF, handshake timeout, TLS Alert (`0x15`), or an injected non-TLS ISP block page (such as an HTTP `302`/`403` redirect), `vdpi` automatically escalates through `ALL_STAGES` without dropping the client session:

| Stage | Strategy | Mechanism |
| :---: | :--- | :--- |
| **1** | `Primary` (`ComboMultiRecord`) | Configured primary mode (default `combo`: splits the TLS `ClientHello` into 4 wire-paced RFC-compliant `0x16` records across the handshake header and SNI midpoint to defeat OS TCP coalescing and shallow DPI). |
| **2** | `FineFragment` | Keeps a single intact outer TLS record split across 4 wire-paced TCP segments (for strict servers or firewalls that reject multi-record `ClientHello`s). |
| **3** | `DeepRecordStorm` | Emits 12+ wire-paced `0x16` records (up to 10 tiny 2-byte lead records exhausting hardware DPI per-flow packet caps before SNI hits the wire, followed by SNI-split records). |
| **4** | `SlowSniSlice` | Single intact outer TLS record with 2-byte paced SNI slicing and a 20ms midpoint gap for strict servers behind stateful burst-reassembling DPI. |
| **5** | `OobSniDesync` | Injects 1 TCP Out-of-Band (`MSG_OOB`, `URG=1`) decoy byte at the SNI midpoint. Real server TCP stacks (`SO_OOBINLINE=0`) strip the urgent byte cleanly while stateful DPI boxes see a corrupted hostname and pass the flow through. |
| **6** | `MultiRecordOob` | Combines 4-record TLS splitting with a `MSG_OOB` urgent decoy byte at the TLS record boundary inside SNI, shifting subsequent TLS record framing for stateful DPI state machines. |
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
| **Windows** | `%LOCALAPPDATA%\vdpi\adaptive-cache.json` (interactive/foreground); `%ProgramData%\vdpi\adaptive-cache.json` (Windows Service) |
| **macOS** | `~/Library/Caches/vdpi/adaptive-cache.json` |
| **Linux** | `$XDG_CACHE_HOME/vdpi/adaptive-cache.json` (fallback: `~/.cache/vdpi/adaptive-cache.json`) |
| **Android / iOS** | Managed automatically inside the app cache / iOS App Group container |
