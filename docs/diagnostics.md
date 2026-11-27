# Diagnostics and Troubleshooting

This guide explains how to inspect live `vdpi` health with `vdpi status`, verify end-to-end bypass behavior with `vdpi doctor`, and resolve common desktop and mobile issues.

On **Android** and **iOS**, open **Diagnostics** from the main Tunnel screen to run live DoH and real `rustls` TLS 1.3/1.2 probes directly through the desync engine, copy the chronological engine event log, or export a shareable diagnostics report.

On **Desktop**, use `vdpi status` and `vdpi doctor`.

---

## `vdpi status`

```bash
vdpi status
vdpi status --json   # Machine-readable JSON output
```

`vdpi status` inspects the installed background service, queries live daemon telemetry, and prints OS integration state without sending internet traffic.

### What `vdpi status` Reports

#### Shared Fields (Both Modes)
- **Active Engine Mode**: `Engine (TUN)` or `Engine (Proxy)` header showing the live engine summary (interface/uplink or bind address, plus process RSS memory), or `NOT RESPONDING` if no daemon answers `/vdpi-health`.
- **VPN Conflict**: Shown (`VPN Conflict`) whenever a full-tunnel third-party VPN is detected (including yielded standby or `[kill-switch]` status).
- **Anti-DPI Engine**: Active desync mode (`combo`, `tls-record`, `fragment`, `split`), DoH state (`on`/`off`), QUIC blocking (`blocked`/`allowed`), and the current ISP-wide stage (`ISP stage=...`).
- **DNS Server**: Active and configured upstream DNS/DoH resolver (with custom `https://` DoH profile paths and query tokens redacted for privacy).
- **Live Telemetry**: Active and total connection counts, cached adaptive hosts (`adaptive-cache.json`), active Cone-NAT UDP flows, QUIC blocked count, intercepted DNS queries, and process RSS memory.
- **Service State**:
  - Windows: Native Windows Service (`vdpi`) state (`RUNNING`, `STOPPED`, `NOT INSTALLED`), start type, PID, `Service Command`, and any legacy `HKCU Run` startup entry warning.
  - macOS: `LaunchDaemon plist (TUN)` (`/Library/LaunchDaemons/com.vdpi.daemon.plist`, when installed) and `LaunchAgent plist` (`~/Library/LaunchAgents/com.vdpi.plist`) with state (`running`, `paused`, `not installed`).
  - Linux: `systemd system unit (TUN)` (`/etc/systemd/system/vdpi.service`, when installed) and `systemd user unit` (`~/.config/systemd/user/vdpi.service`) with state (`running`, `paused`, `not installed`).

#### TUN Mode Details
- **Engine (TUN)**: Active virtual interface (`vdpi0` on Windows/Linux, `utunN` on macOS), detected physical uplink NIC (`via <nic>`), and process RSS memory. The desktop TUN adapter uses virtual IP `198.18.0.1`, virtual DNS endpoint `198.18.0.2`, and MTU `16384` (`TunProfile::DESKTOP`: up to `512` TCP sessions, `512` Cone-NAT UDP flows, `256` inflight DNS queries, `448 KiB` TCP buffers, `256 KiB` UDP socket buffers).
- **Health Endpoint**: Loopback `/vdpi-health` listener address and port (default `127.0.0.1:18089`) with `RUNNING` status.
- **TUN Counters (in `Live Telemetry`)**: Active/total connections, cached hosts, active Cone-NAT UDP flows, **QUIC blocked** counter (UDP/443 datagrams dropped to force TCP TLS fallback), intercepted DNS queries, and process RSS memory.
- **VPN Conflict**: Reported when a third-party full-tunnel VPN is detected (for example `Mullvad (yielded)` under `auto-yield` or `Mullvad (wg0)` under `warn`).

#### Proxy Mode Details
- **Engine (Proxy)**: Bound address/port and process RSS memory.
- **Primary HTTP/CONNECT/Auto**: Bound address and port (default `127.0.0.1:8080`) and live `/vdpi-health` status (`RUNNING (...)` or `NOT RESPONDING`). Automatically discovers rotated ports via `state.json`.
- **Dedicated SOCKS5 (TCP/UDP)**: Bound address and port (default `127.0.0.1:1080`) and `LISTENING` / `CLOSED` / `UNREACHABLE` / `DISABLED` status.
- **OS System Proxy State**:
  - Windows: WinINET `AutoConfigURL` (fail-open PAC `http://127.0.0.1:<port>/vdpi.pac`), `ProxyEnable`/`ProxyServer`/`ProxyOverride`, WinHTTP proxy (`netsh winhttp`), and user environment `HTTPS_PROXY` (for detecting legacy fail-closed leftovers).
  - macOS: `networksetup` `AutoProxyURL` (fail-open PAC) plus HTTP/HTTPS/SOCKS proxy state per active network service, and `launchctl` environment variables.
  - Linux: GNOME `gsettings` (`org.gnome.system.proxy` `mode`/`autoconfig-url`), KDE `kioslaverc` (`ProxyType`/`Proxy Config Script`), and `systemd --user` `HTTPS_PROXY` state.

---

## `vdpi doctor`

```bash
vdpi doctor
```

`vdpi doctor` begins with **`=== VPN Conflict Check ===`** (and on Windows, **`=== Windows TUN Preflight (Wintun) ===`** verifying `wintun.dll` SHA-256). When no daemon is running, it immediately runs **`=== System Proxy & Adapter Hygiene Checks ===`** (checking stale OS proxy drift, Windows `ALL_PROXY`/WinHTTP, and `Orphaned TUN Adapter`) before launching ephemeral live probes so orphaned adapters are flagged without waiting on timeouts. When a Proxy daemon is live, it runs the live Discord/Roblox probes followed by **`=== Proxy Session & Browser Checks ===`**, exiting non-zero if any required check fails.

### TUN Mode Checks

When the desktop daemon is active in TUN mode, `vdpi doctor` verifies the transparent network path directly through the OS routing table and virtual adapter:

1. **VPN Conflict Check (`=== VPN Conflict Check ===`)**: Checks active system routes and tunnel interfaces for third-party full-tunnel VPNs (WireGuard, Mullvad, ProtonVPN, OpenVPN, Cloudflare WARP) vs split-tunnel overlays (such as Tailscale mesh).
2. **Direct HTTPS via TUN (`=== Direct HTTPS via TUN Checks ===`)**: Issues direct HTTPS requests (with no HTTP/SOCKS proxy configured) against Roblox ClientSettings, Discord Web, Discord Gateway, and Roblox Web to confirm packets traverse the TUN interface and pass 7-stage adaptive TLS desynchronization.
3. **TUN UDP DNS & QUIC Checks (`=== TUN UDP DNS & QUIC Checks ===`)**:
   - **UDP DNS (`discord.com`)**: Sends a UDP DNS query to `1.1.1.1:53` routed through the TUN interface (where `vdpi` intercepts port-53 DNS traffic, alongside queries addressed to the virtual DNS endpoint `198.18.0.2`) to verify resolution via `vdpi`'s anti-poisoning RFC 8484 DoH ring and absence of ISP sinkhole IPs.
   - **QUIC Drop Counter**: Sends an RFC 9000 QUIC v1 Initial probe to `1.1.1.1:443` and checks that the TUN `quic_blocked` counter increments when `block_quic` is enabled, ensuring browsers fall back cleanly to HTTP/2 over desynchronized TCP TLS instead of failing with `ERR_QUIC_PROTOCOL_ERROR`.

### Proxy Mode Checks

When running in Proxy mode (or when no daemon is running, in which case `vdpi doctor` spawns an ephemeral in-process engine on random loopback ports without altering OS proxy settings), `vdpi doctor` runs:

1. **VPN Conflict Check (`=== VPN Conflict Check ===`)**: Reports whether a full-tunnel third-party VPN or split-tunnel overlay is active.
2. **System Proxy & Adapter Hygiene Checks (`=== System Proxy & Adapter Hygiene Checks ===`)** *(when stopped / ephemeral - runs before live ephemeral probes)*: Immediately checks stale **System Proxy Drift** (including Windows `ALL_PROXY`/WinHTTP leftovers) and **Orphaned TUN Adapter** before launching the ephemeral engine so orphaned adapters are flagged without waiting on probe timeouts.
3. **HTTP/HTTPS `CONNECT` Tunnel Checks (`=== HTTP/HTTPS CONNECT Tunnel Checks ===`)**: Connects via the HTTP proxy listener (`127.0.0.1:8080` by default, or the ephemeral loopback port) to 11 Discord and Roblox endpoints.
4. **SOCKS5h Checks (`=== SOCKS5h (Remote DoH + TLS DPI Desync) Checks ===`)**: Connects via `socks5h://` (`127.0.0.1:1080` by default, or the ephemeral loopback port) so DNS resolution happens inside `vdpi`'s DoH ring rather than the local stub resolver.
5. **Proxy Session & Browser Checks (`=== Proxy Session & Browser Checks ===`)** *(live Proxy daemon - runs after live probes)*: Checks **Stale Browsers**, **System Proxy Drift** (whether Windows `AutoConfigURL`, macOS `AutoProxyURL`, or Linux GNOME/KDE PAC points to a different `vdpi` port, or whether stale legacy fail-closed `ProxyEnable=1` / `HTTP_PROXY` / `HTTPS_PROXY` entries remain), and **Orphaned TUN Adapter**.

### Example `vdpi doctor` Output (Proxy Mode)

```text
=== VPN Conflict Check ===
  [PASS] VPN Conflict             -> none detected

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

=== Proxy Session & Browser Checks ===
  [PASS] Stale Browsers           -> none detected
  [PASS] System Proxy Drift       -> aligned with 127.0.0.1:8080
  [PASS] Orphaned TUN Adapter     -> none detected

All Discord & Roblox HTTP CONNECT and SOCKS5h checks passed.
```

> Note: HTTP `404` on root API endpoints (`apis.roblox.com`, `gamejoin.roblox.com`) is expected and counts as `[PASS]` because the TLS handshake completed and the origin server responded cleanly.

---

## Interactive TUI Screens (Diagnostics & Software Update)

Launching `vdpi` (Control Center TUI) provides two built-in interactive `ratatui` screens without leaving the terminal:

- **Network Diagnostics** (Control Center -> **Run diagnostics**): Executes 5 live checks (6 on Windows, adding **Wintun Driver (`wintun.dll`)**) with progress spinners, per-probe latencies, scrollable output (`↑`/`↓`, `j`/`k`, `PgUp`/`PgDn`), and one-key re-run (`r`):
  1. **Service & Engine** - daemon reachability, active TUN/Proxy mode, version, RSS memory, and desync mode.
  2. **VPN & Split Tunnel** - `VpnGuard` conflict check plus active per-app split-tunnel policy.
  3. **Wintun Driver (`wintun.dll`)** *(Windows only)* - verifies the pinned WHQL-signed `wintun.dll` SHA-256 for TUN mode.
  4. **Encrypted DNS (DoH)** - live RFC 8484 DoH resolution check.
  5. **TLS Handshake (`discord.com`)** - live TLS bypass verification.
  6. **TLS Handshake (`roblox.com`)** - live TLS bypass verification.
- **Software Update** (Control Center -> **Check for updates online**): Queries GitHub Releases, displays current vs. latest version status (`UpToDate`, `Available`, or `Unknown`) with scrollable release notes, lets you re-check (`r`), and downloads, SHA-256-verifies, and installs updates in place.

---

## Common Troubleshooting

### Antivirus / Windows Defender False Positives

Unsigned Rust binaries that perform low-level socket manipulation, and the `wintun.dll` adapter library used in Windows TUN mode, can occasionally trigger heuristic alerts in Windows Defender, SmartScreen, or third-party antivirus suites.

1. **Verify integrity first**: Before allowing any binary, verify its SHA-256 digest against the release `SHA256SUMS.txt` (see [SECURITY.md](../SECURITY.md#binary-verification)).
2. **Add an exclusion if quarantined**: If Windows Defender quarantines `vdpi.exe` or `wintun.dll`, restore it from Protection History and add a folder exclusion for `%ProgramFiles%\vdpi` (or your local build directory).
3. **Reinstall cleanly**: If files were partially stripped by antivirus software, run `vdpi update --force` after adding the exclusion.

### Apps Ignoring Proxy PAC vs Switching to TUN Mode

In **Proxy mode**, Windows and macOS configure a fail-open `/vdpi.pac` auto-config script (`AutoConfigURL` / `AutoProxyURL`) with zero `HTTP_PROXY`/`HTTPS_PROXY` environment variables; Linux configures GNOME/KDE PAC plus optional `systemd --user` `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` environment variables (disabled via `--no-env-proxy`).

- Browsers (Chrome, Edge, Firefox) and Electron apps (Discord) adopt `/vdpi.pac` dynamically without needing a restart, and fall back to `DIRECT` automatically if `vdpi` stops or crashes.
- Native game clients and `libcurl`-based apps (such as `RobloxPlayerBeta.exe`) ignore OS PAC scripts and connect directly unless configured to use `127.0.0.1:8080` / `:1080`.

**Fix:** Switch to **TUN mode** (`vdpi engine tun` or `vdpi --tun start`). Transparent TUN captures all TCP, UDP, and DNS traffic at the IP layer with zero proxy configuration.

#### Cleaning Up Stale Proxy Settings

Because `/vdpi.pac` fails open (`PROXY 127.0.0.1:<port>; DIRECT`), a stale PAC URL will not block internet access, but you can clean up leftover settings from a forced power loss or older pre-PAC build:

- **Windows:**
  1. Open **Settings > Network & internet > Proxy**, turn off **Use setup script** if `AutoConfigURL` still points to `http://127.0.0.1:<port>/vdpi.pac`, and turn off **Use a proxy server** if an older build left `127.0.0.1:8080` set.
  2. If upgrading from an older version left stale `HTTP_PROXY`, `HTTPS_PROXY`, or `NO_PROXY` entries pointing to `127.0.0.1` in **Edit environment variables for your account**, remove them (or run `vdpi pause` / restart `vdpi` to auto-clean them).
  3. Run `vdpi status` to confirm `AutoConfigURL (PAC)`, `ProxyEnable`, `WinHTTP Proxy`, and `User Env HTTPS_PROXY` are clean.
- **macOS:** Disable any stale `/vdpi.pac` `AutoProxyURL` on active network services with `networksetup -setautoproxystate "Wi-Fi" off` (or run `vdpi pause`).
- **Linux:** Reset GNOME (`gsettings set org.gnome.system.proxy mode 'none'`), KDE (`kwriteconfig6` on Plasma 6 or `kwriteconfig5` on Plasma 5: `kwriteconfig6 --file kioslaverc --group 'Proxy Settings' --key ProxyType 0` / `kwriteconfig5 --file kioslaverc --group 'Proxy Settings' --key ProxyType 0`), and `systemd --user` session env vars (`systemctl --user unset-environment HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY no_proxy`), or run `vdpi pause`.

### VPN Active Standby (`auto-yield`)

When `vdpi` runs in **TUN mode** with the default `--vpn-coexistence auto-yield` policy and you connect a full-tunnel third-party VPN (WireGuard, Mullvad, ProtonVPN, OpenVPN, Cloudflare WARP):

- `vdpi` automatically enters **active standby**, releasing its TUN routes and virtual DNS so the VPN establishes cleanly without route conflicts or packet loops.
- `vdpi status` reports the VPN coexistence state as yielded/standby.
- When the third-party VPN disconnects, `vdpi` detects the route change and re-engages TUN protection automatically.

If you need different behavior:
- To keep `vdpi` running alongside a VPN without TUN route contention, switch to Proxy mode (`vdpi engine proxy`), which operates purely on loopback (`127.0.0.1`) with no virtual adapter.
- To see conflict warnings without automatic yielding, set `vpn_coexistence = "warn"` in `config.toml` (or `--vpn-coexistence warn`).
- To disable VPN detection entirely (for split-tunnel or custom routing setups), set `vpn_coexistence = "off"` (or `--vpn-coexistence off`).

### Repairing or Reinstalling with `vdpi update --force`

If an upgrade was interrupted, a file was quarantined by antivirus, or the background service command drifted out of sync:

```bash
vdpi update --force
```

`vdpi update --force` downloads the latest GitHub Release archive for your OS/architecture, verifies its SHA-256 digest against `SHA256SUMS.txt`, replaces the installed binary, and refreshes the registered background service (Windows Service / macOS `LaunchDaemon` or `LaunchAgent` / Linux `systemd`) automatically.

If connections stall after switching ISPs or mobile networks, clear the learned per-host adaptive stage cache:
- In the foreground dashboard (`vdpi start`), press **`c`** to clear `adaptive-cache.json`.
- On Android or iOS, use **Clear Cache** in Settings.

### Mobile Troubleshooting Quick Notes

- **Android Private DNS**: If Android's system Private DNS is pinned to a custom hostname blocked by your ISP, set Private DNS to **Automatic** or **Off** so DNS uses `vdpi`'s built-in RFC 8484 DoH ring.
- **Android Battery Optimization**: On Xiaomi (MIUI/HyperOS), Samsung, Oppo, and Huawei devices, set **vdpi** battery usage to **Unrestricted / No restrictions** so the OS does not kill the local `VpnService` when the screen locks. Do not enable *"Block connections without VPN"* lockdown mode if you use per-app bypass rules.
- **iOS Local VPN Slot**: Both Android (`VpnService`) and iOS (`NEPacketTunnelProvider`) occupy the OS's single active Personal VPN slot, so another VPN app cannot be connected simultaneously on mobile.
