# VPN Coexistence, Split Overlays, and Domain Bypass

`vdpi` is designed to run alongside both full-tunnel VPN clients and local/overlay networking tools without manual toggling or broken routes, while keeping sensitive banking, government, gaming, and local domains untouched.

---

## Full-Tunnel VPN Coexistence (`VpnGuard`)

When a full-tunnel VPN is active, your traffic is already encrypted inside the VPN tunnel and exits through the VPN server rather than your ISP's DPI equipment. Keeping a local TUN adapter or conflicting system proxy active on top of a full-tunnel VPN can cause route conflicts, double-encapsulation failures, or broken DNS.

### Supported Full-Tunnel VPNs

`VpnGuard` monitors OS routing tables and network interface state to detect full-tunnel VPN takeover from:

- **Mullvad**
- **WireGuard** (full-tunnel `0.0.0.0/0` or `0.0.0.0/1` + `128.0.0.0/1` peers)
- **OpenVPN** (TUN/TAP default-route tunnels)
- **NordVPN** (NordLynx / OpenVPN)
- **ProtonVPN** (WireGuard / OpenVPN)
- **Cloudflare WARP** (full-tunnel mode)
- **Tailscale Exit Node** (when an Exit Node is actively enabled)

`VpnGuard` distinguishes a **full-tunnel VPN** (a non-`vdpi` virtual tunnel interface holding the active default or split-default internet route) from a **split-overlay** network (which only routes its private overlay CIDR). Connecting to a split overlay never triggers a yield.

### `vpn_coexistence` Modes

Configure behavior in `config.toml` via `vpn_coexistence`:

| Value | Behavior |
| :--- | :--- |
| `"auto-yield"` *(default)* | **0ms instant yield** the moment a full-tunnel VPN takes over internet routing: `vdpi` immediately yields TUN routes/adapter (or suspends conflicting proxy takeover) so the VPN takes full control with zero blackholed packets. When the VPN disconnects, `vdpi` waits **3 seconds** (debouncing VPN server switches and brief reconnects) and automatically recovers full anti-DPI protection. |
| `"warn"` | Keeps `vdpi` active without tearing down automatically, surfacing a VPN conflict warning badge in `vdpi status` and the Control Center TUI. |
| `"off"` | Disables `VpnGuard` detection completely. Use only if you manage custom routing tables or split-tunneling rules manually. |

Example `config.toml` setting:

```toml
vpn_coexistence = "auto-yield"
```

> **Mobile note (Android & iOS):** Android (`VpnService`) and iOS (`NEPacketTunnelProvider`) allow only one active Personal VPN slot at a time. Starting a third-party VPN app on mobile automatically replaces `vdpi`'s local VPN session at the OS level.

---

## Split-Overlay and Local Tools Alongside TUN Mode

Desktop TUN mode keeps all private, link-local, loopback, CGNAT, multicast, and container/VM networks on their native kernel routes using platform-native routing isolation:

- **Windows:** Installs **65 non-overlapping public IPv4 complement CIDRs** on the `vdpi0` Wintun adapter (an exact complement of `0.0.0.0/0` minus RFC 1918, CGNAT, `192.0.0.0/24`, loopback, link-local, multicast, and reserved ranges), never claiming `0.0.0.0/0`.
- **macOS:** Installs **8 non-zero-anchor IPv4 split routes** (`1.0.0.0/8`, `2.0.0.0/7`, `4.0.0.0/6`, `8.0.0.0/5`, `16.0.0.0/4`, `32.0.0.0/3`, `64.0.0.0/2`, `128.0.0.0/1`) on `utun` (leaving `0.0.0.0/8` untouched for `IP_BOUND_IF`), paired with `-ifscope` physical default routes, explicit LAN/CGNAT/link-local exclusion routes (`10.0.0.0/8`, `100.64.0.0/10`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `224.0.0.0/4`, `240.0.0.0/4`), and session-scoped `SCDynamicStore` DNS, while more-specific native overlay routes (such as Tailscale) keep priority.
- **Linux:** Uses `SO_MARK` (`0x5644`) policy routing (`ip rule`) with `lookup main suppress_prefixlength 0` and `iif lo lookup 202`, so all non-default routes in `main` (LAN, Docker bridges, link-local, Tailscale, split-tunnel WireGuard) and forwarded container/VM traffic stay native.

| Tool / Traffic Class | Subnets / Domains Left Untouched | Notes |
| :--- | :--- | :--- |
| **Tailscale mesh** | `100.64.0.0/10` (CGNAT), `fd7a:115c:a1e0::/48`, `*.ts.net` | Peer-to-peer mesh traffic and MagicDNS bypass TUN directly. Only enabling a **Tailscale Exit Node** triggers `VpnGuard` `auto-yield`. |
| **Docker** | `172.16.0.0/12`, `192.168.0.0/16` bridges & overlays | Container-to-host, published ports, and inter-container networks stay native. |
| **WSL / Hyper-V** | `172.16.0.0/12` virtual switches, `localhost` forwarding | Linux subsystem networking and host-guest localhost relay work untouched. |
| **VMware / VirtualBox** | `192.168.0.0/16`, `10.0.0.0/8` host-only & NAT adapters | Guest VMs route normally without passing through `vdpi`. |
| **LAN & private networks** | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `::1/128`, `fc00::/7`, `fe80::/10` | Routers, NAS devices, dev servers, and local web UIs go straight to the physical NIC. |
| **mDNS** | `224.0.0.251`, `ff02::fb`, `*.local` | Multicast stays native and `*.local` queries resolve directly via the OS resolver (bypassing DoH filtering). |
| **SMB / local shares & printers** | LAN IPs, `.lan`, `.home.arpa`, `.internal`, Windows `<local>` | File shares, AirPrint/IPP printers, and intranet hosts suffer zero tunnel overhead. |

---

## Default Bypassed Domains

Strict banking WAFs, payment processors, government TLS endpoints, game anticheat/auth servers, and local/mesh domains can reject fragmented or OOB-desynchronized TLS `ClientHello` packets. `vdpi` bypasses these automatically (`DEFAULT_BYPASS_PATTERNS`) so connections pass through unmodified:

| Category | Built-In Default Patterns |
| :--- | :--- |
| **Local LANs & mesh** | `localhost`, `*.local`, `*.lan`, `*.internal`, `*.home.arpa`, `*.ts.net`, plus all loopback, RFC 1918, CGNAT (`100.64.0.0/10`), link-local, IETF protocol (`192.0.0.0/24`), benchmark (`198.18.0.0/15`), ULA, multicast, and reserved/broadcast/unspecified IPs |
| **OS captive-portal probes** | `captive.apple.com`, `www.msftconnecttest.com`, `msftncsi.com`, `dns.msftncsi.com`, `ipv6.msftconnecttest.com`, `detectportal.firefox.com`, `connectivitycheck.gstatic.com`, `connectivitycheck.android.com`, `clients3.google.com`, `nmcheck.gnome.org`, `networkcheck.kde.org`, `neverssl.com` |
| **Government & public portals** | `*.gov`, `*.mil`, `*.int`, `*.gov.uk`, `*.gov.tr`, `*.bel.tr`, `*.pol.tr`, `*.tsk.tr`, `*.kep.tr`, `*.edu.tr`, `*.org.tr`, `*.osym.gov.tr`, `*.edevlet.gov.tr`, `*.turkiye.gov.tr`, `*.turktelekom.com.tr`, `*.pttavm.com` |
| **Turkish banks & telecoms** | `*.halkbank.com.tr`, `*.isbank.com.tr`, `*.akbank.com`, `*.akbank.com.tr`, `*.garanti.com.tr`, `*.garantibbva.com.tr`, `*.ziraatbank.com.tr`, `*.yapikredi.com.tr`, `*.vakifbank.com.tr`, `*.qnb.com.tr`, `*.qnbfinansbank.com`, `*.qnbfinansbank.com.tr`, `*.denizbank.com`, `*.enpara.com`, `*.ing.com.tr`, `*.teb.com.tr`, `*.kuveytturk.com.tr`, `*.albaraka.com.tr`, `*.odeabank.com.tr`, plus additional Turkish bank/payment/telecom portals (`DEFAULT_BYPASS_PATTERNS`) |
| **Payment gateways & marketplaces** | `*.bkm.com.tr`, `*.paratika.com.tr`, `*.iyzico.com`, `*.iyzipay.com`, `*.paytr.com`, `*.papara.com`, `*.sahibinden.com`, `*.shbdn.com` |
| **Riot / Valorant** | `*.riotgames.com`, `*.riotcdn.net`, `*.playvalorant.com`, `*.pvp.net`, `*.rgpub.io` (strict TLS and anticheat/game handshakes pass through unmodified) |

In **TUN mode**, bypassed hosts pass through unmodified without TLS fragmentation or QUIC blocking. In **Proxy mode**, the fail-open `/vdpi.pac` script routes localhost, single-label LAN hostnames, private LAN/CGNAT/IPv6 ULA ranges (`10.*`, `100.64.0.0/10`, `127.*`, `169.254.*`, `172.16.0.0/12`, `192.168.*`, `fc00::/7`, `fe80::/10`), local/mesh namespaces (`*.local`, `*.localhost`, `*.localdomain`, `*.lan`, `*.internal`, `*.home.arpa`, `*.ts.net`, `lvh.me`/`nip.io`/`sslip.io`/`localtest.me`), captive-portal probes, and custom `bypass_domains` (including IPv4 CIDRs) directly (`DIRECT`). macOS and Linux GNOME/KDE also keep OS proxy bypass lists synchronized, and any bypassed public domain, wildcard, CIDR, or IP that reaches the proxy passes through unmodified via `BypassPolicy`.

---

## Customizing Bypass and Include Rules

### Evaluation Order and Syntax

`vdpi` evaluates every connection against `BypassPolicy` in this order:

1. **Non-public IP & local LAN check:** Any loopback, RFC 1918, CGNAT, link-local, benchmark (`198.18.0.0/15`), multicast, reserved, or ULA IP literal (or resolved IP), and local LAN namespaces (`localhost`, `*.local`, `*.lan`, `*.home.arpa`, `*.internal`, `*.ts.net`, single-label hostnames) are always bypassed.
2. **User bypass rules (`bypass_domains` / `--bypass`):** Your explicit custom entries always take precedence over `include_domains`.
   - Exact domain (`example.com`) matches both `example.com` and any subdomain (`*.example.com`).
   - Leading wildcard (`*.example.com`) matches `example.com` and all subdomains.
   - General wildcard (`*bank.com.tr`) matches any suffix containing that wildcard pattern.
   - CIDR prefixes (such as `203.0.113.0/24` or `2001:db8::/32`) and IP literals (such as `198.51.100.7`) are parsed and matched directly by `BypassPolicy` against destination and resolved IPs (including IPv4-mapped IPv6) in **both TUN and Proxy modes**.
3. **Include rules (`include_domains` / `--include`):** Optional allowlist of regular expressions.
   - When **empty** (default), all non-bypassed public hosts (excluding `DEFAULT_BYPASS_PATTERNS`) receive adaptive DPI desync.
   - When **non-empty**, `vdpi` switches to **allowlist mode**: hostnames matching an include regex receive DPI desync (overriding built-in `DEFAULT_BYPASS_PATTERNS` such as `*.org.tr`, while `LocalLan` and explicit user `--bypass` rules still win); all other hosts pass through unmodified.

### Configuring in `config.toml`

Run `vdpi config` to inspect or locate your active `config.toml`, then edit the keys directly:

```toml
# Engine and VPN coexistence
engine = "tun"
vpn_coexistence = "auto-yield"

# Additional domains/wildcards that should never be fragmented
bypass_domains = [
    "*.corp.example.com",
    "mybank.example.net",
    "*.internal-tool.org",
]

# Optional: restrict DPI desync ONLY to matching regexes (leave empty for all non-bypassed hosts)
include_domains = [
    '(discord|roblox)\.(com|gg|media)$',
]
```

After updating `config.toml`, restart the service (`vdpi pause && vdpi resume`) or restart your foreground session to apply changes.

### Configuring via CLI Flags

Both flags are repeatable and work with `vdpi start` and `vdpi install`:

```sh
# Bypass additional domains for a single foreground session
vdpi start --bypass "*.corp.example.com" --bypass "mybank.example.net"

# Apply DPI desync ONLY to Discord and Roblox (allowlist mode)
vdpi start --include '(discord|roblox)\.(com|gg|media)$'

# Combine custom bypass rules with a background service install
vdpi install --tun --bypass "*.corp.example.com" --bypass "vpn.example.org"
```

---

## Per-App Split Tunneling

Per-app split tunneling lets you control which desktop applications receive anti-DPI TLS desync and UDP/443 QUIC blocking in **both TUN and Proxy modes** (via local socket-to-process resolution), as well as on Android.

| Mode (`split_tunnel_mode`) | Behavior |
| :--- | :--- |
| `all` *(default)* | Protect all applications (subject to domain/IP bypass rules). |
| `exclude` | Bypass applications in `split_tunnel_apps` so their traffic passes through unmodified without TLS fragmentation or QUIC blocking. |
| `include` | Apply anti-DPI desync **only** to applications listed in `split_tunnel_apps`; all other apps pass through unmodified. |

### Interactive Picker, CLI, and `config.toml`

- **Interactive TUI:** Run `vdpi split` (alias `vdpi apps`) or press **`s`** in the Control Center TUI to search running and installed apps, toggle selections, and switch between `all`, `exclude`, and `include`.
- **CLI:**
  ```sh
  vdpi split mode exclude
  vdpi split add steam.exe obs64.exe
  vdpi split list firefox
  vdpi split status --json
  vdpi split remove obs64.exe
  vdpi split clear

  # One-off session override
  vdpi start --tun --split-mode include --split-app Discord.exe --split-app RobloxPlayerBeta.exe
  ```
- **`config.toml`:**
  ```toml
  split_tunnel_mode = "exclude"
  split_tunnel_apps = ["steam.exe", "obs64.exe"]
  ```
