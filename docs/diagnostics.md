# Diagnostics and Troubleshooting

This guide explains how to inspect live `vdpi` health with `vdpi status`, verify end-to-end bypass behavior with `vdpi doctor`, and resolve common desktop and mobile issues.

On **Android** and **iOS**, open **Diagnostics** from the main Tunnel screen to run live DoH and real `rustls` TLS 1.3/1.2 probes directly through the desync engine, copy the chronological engine event log, or export a shareable diagnostics report.

On **Desktop**, use `vdpi status` and `vdpi doctor`.

---

## `vdpi status`

```bash
vdpi status
```

`vdpi status` inspects the installed background service, queries live daemon telemetry, and prints OS integration state without sending internet traffic.

### What `vdpi status` Reports

#### Shared Fields (Both Modes)
- **Active Engine Mode**: `Engine (TUN)` or `Engine (Proxy)` header showing the live engine summary (interface/uplink or bind address, plus process RSS memory), or `NOT RESPONDING` if no daemon answers `/vdpi-health`.
- **VPN Conflict**: Shown (`VPN Conflict`) whenever a full-tunnel third-party VPN is detected (including yielded standby or `[kill-switch]` status).
- **Anti-DPI Engine**: Active desync mode (`combo`, `tls-record`, `fragment`, `split`), DoH state (`on`/`off`), QUIC blocking (`blocked`/`allowed`), and the current ISP-wide stage (`ISP stage=...`).
- **Live Telemetry**: Active and total connection counts, cached adaptive hosts (`adaptive-cache.json`), active Cone-NAT UDP flows, QUIC blocked count, intercepted DNS queries, and process RSS memory.
- **Service State**:
  - Windows: Native Windows Service (`vdpi`) state (`RUNNING`, `STOPPED`, `NOT INSTALLED`), start type, PID, `Service Command`, and any legacy `HKCU Run` startup entry warning.
  - macOS: `LaunchDaemon plist (TUN)` (`/Library/LaunchDaemons/com.vdpi.daemon.plist`, when installed) and `LaunchAgent plist` (`~/Library/LaunchAgents/com.vdpi.plist`) with state (`running`, `paused`, `not installed`).
  - Linux: `systemd system unit (TUN)` (`/etc/systemd/system/vdpi.service`, when installed) and `systemd user unit` (`~/.config/systemd/user/vdpi.service`) with state (`running`, `paused`, `not installed`).

#### TUN Mode Details
- **Engine (TUN)**: Active virtual interface (`vdpi0` on Windows/Linux, `utunN` on macOS), detected physical uplink NIC (`via <nic>`), and process RSS memory. The desktop TUN adapter uses virtual IP `198.18.0.1`, virtual DNS endpoint `198.18.0.2`, and MTU `1500`.
- **Health Endpoint**: Loopback `/vdpi-health` listener address and port (default `127.0.0.1:18089`) with `RUNNING` status.
- **TUN Counters (in `Live Telemetry`)**: Active/total connections, cached hosts, active Cone-NAT UDP flows, **QUIC blocked** counter (UDP/443 datagrams dropped to force TCP TLS fallback), intercepted DNS queries, and process RSS memory.
- **VPN Conflict**: Reported when a third-party full-tunnel VPN is detected (for example `Mullvad (yielded)` under `auto-yield` or `Mullvad (wg0)` under `warn`).

#### Proxy Mode Details
- **Engine (Proxy)**: Bound address/port and process RSS memory.
- **Primary HTTP/CONNECT/Auto**: Bound address and port (default `127.0.0.1:8080`) and live `/vdpi-health` status (`RUNNING (...)` or `NOT RESPONDING`). Automatically discovers rotated ports via `state.json`.
- **Dedicated SOCKS5 (TCP/UDP)**: Bound address and port (default `127.0.0.1:1080`) and `LISTENING` / `CLOSED` / `UNREACHABLE` / `DISABLED` status.
- **OS System Proxy State**:
  - Windows: WinINET registry (`ProxyEnable`, `ProxyServer`, `ProxyOverride`), WinHTTP proxy (`netsh winhttp`), and user environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`).
  - macOS: `networksetup` HTTP/HTTPS/SOCKS proxy state per active network service and `launchctl` environment variables.
  - Linux: GNOME `gsettings` / KDE `kioslaverc` proxy state and `systemctl --user` environment variables.

---

## `vdpi doctor`

```bash
vdpi doctor
```

`vdpi doctor` always begins with a **`=== VPN Conflict Check ===`**, then executes live end-to-end probes against real Discord and Roblox endpoints and exits non-zero if any required check fails.

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
2. **HTTP/HTTPS `CONNECT` Tunnel Checks (`=== HTTP/HTTPS CONNECT Tunnel Checks ===`)**: Connects via the HTTP proxy listener (`127.0.0.1:8080` by default) to 11 Discord and Roblox endpoints.
3. **SOCKS5h Checks (`=== SOCKS5h (Remote DoH + TLS DPI Desync) Checks ===`)**: Connects via `socks5h://` (`127.0.0.1:1080` by default) so DNS resolution happens inside `vdpi`'s DoH ring rather than the local stub resolver.
4. **Proxy Session & Browser Checks (`=== Proxy Session & Browser Checks ===`)** *(live daemon only)*: Checks for **Stale Browsers** started before proxy environment activation and **System Proxy Drift** where OS proxy settings or `HTTP_PROXY`/`HTTPS_PROXY` point to a different address/port than the active daemon.

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

All Discord & Roblox HTTP CONNECT and SOCKS5h checks passed.
```

> Note: HTTP `404` on root API endpoints (`apis.roblox.com`, `gamejoin.roblox.com`) is expected and counts as `[PASS]` because the TLS handshake completed and the origin server responded cleanly.

---

## Common Troubleshooting

### Antivirus / Windows Defender False Positives

Unsigned Rust binaries that perform low-level socket manipulation, and the `wintun.dll` adapter library used in Windows TUN mode, can occasionally trigger heuristic alerts in Windows Defender, SmartScreen, or third-party antivirus suites.

1. **Verify integrity first**: Before allowing any binary, verify its SHA-256 digest against the release `SHA256SUMS.txt` (see [SECURITY.md](../SECURITY.md#binary-verification)).
2. **Add an exclusion if quarantined**: If Windows Defender quarantines `vdpi.exe` or `wintun.dll`, restore it from Protection History and add a folder exclusion for `%ProgramFiles%\vdpi` (or your local build directory).
3. **Reinstall cleanly**: If files were partially stripped by antivirus software, run `vdpi update --force` after adding the exclusion.

### Browser Restart Needed in Proxy Mode vs Switching to TUN Mode

In **Proxy mode** on Windows, browsers (Chrome, Edge) and Discord read Windows WinINET proxy settings dynamically, while native game clients and `libcurl`-based apps (such as `RobloxPlayerBeta.exe`) ignore WinINET and rely on `HTTP_PROXY` / `HTTPS_PROXY` environment variables or WinHTTP.

- When you start `vdpi start` in foreground Proxy mode, `vdpi` leases both WinINET and user environment variables (`HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`).
- Processes that were **already running** before `vdpi` started do not inherit new environment variables. If you launch Roblox via `roblox-player://` from an already-open Chrome/Edge window, the child process inherits the browser's old environment without `HTTPS_PROXY`.

**Fixes (pick one):**
1. **Switch to TUN mode (recommended)**: Run `vdpi engine tun` (or `vdpi --tun start`). Transparent TUN captures all TCP/UDP/DNS traffic at the IP layer with no proxy environment variables and no browser restarts required.
2. **Install the background service**: Run `vdpi install` once so `HTTP_PROXY`/`HTTPS_PROXY` and WinHTTP are already present when you log in.
3. **Restart the browser once**: Close and reopen Chrome/Edge after starting foreground Proxy mode.

#### Cleaning Up Stale Proxy Settings on Windows

If an older build or forced power loss left a stale manual proxy behind:
1. Open **Settings > Network & internet > Proxy** and turn off **Use a proxy server** if it points to `127.0.0.1:8080` (or another old `vdpi` port).
2. Check your user environment variables (**Edit environment variables for your account**) and remove stale `HTTP_PROXY`, `HTTPS_PROXY`, or `NO_PROXY` entries pointing to `127.0.0.1`.
3. Reopen affected browsers or terminals, or run `vdpi status` to confirm a clean state.

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

`vdpi update --force` downloads the latest GitHub Release archive for your OS/architecture, verifies its SHA-256 digest against `SHA256SUMS.txt`, replaces the installed binary, and refreshes the registered background service (Windows Service / `LaunchAgent` / `systemd`) automatically.

If connections stall after switching ISPs or mobile networks, clear the learned per-host adaptive stage cache:
- In the foreground dashboard (`vdpi start`), press **`c`** to clear `adaptive-cache.json`.
- On Android or iOS, use **Clear Cache** in Settings.

### Mobile Troubleshooting Quick Notes

- **Android Private DNS**: If Android's system Private DNS is pinned to a custom hostname blocked by your ISP, set Private DNS to **Automatic** or **Off** so DNS uses `vdpi`'s built-in RFC 8484 DoH ring.
- **Android Battery Optimization**: On Xiaomi (MIUI/HyperOS), Samsung, Oppo, and Huawei devices, set **vdpi** battery usage to **Unrestricted / No restrictions** so the OS does not kill the local `VpnService` when the screen locks. Do not enable *"Block connections without VPN"* lockdown mode if you use per-app bypass rules.
- **iOS Local VPN Slot**: Both Android (`VpnService`) and iOS (`NEPacketTunnelProvider`) occupy the OS's single active Personal VPN slot, so another VPN app cannot be connected simultaneously on mobile.
