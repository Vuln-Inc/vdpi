# CLI and Configuration Reference

This guide covers every `vdpi` command, CLI option, and `config.toml` setting for Windows, macOS, and Linux.

## Usage

```text
vdpi [OPTIONS] [COMMAND]
```

Running `vdpi` with no arguments opens the interactive `ratatui` Control Center TUI (or starts directly in the foreground if a `run-directly` preference was saved next to the binary).

---

## Commands

| Command | Alias | Description |
| :--- | :--- | :--- |
| `vdpi` | - | Open the interactive Control Center TUI (live service/engine telemetry, pause/resume, install/update, diagnostics, uninstall). |
| `vdpi start` | `run` | Start the `vdpi` engine in the foreground without opening the Control Center. Launches the live `ratatui` foreground dashboard on interactive terminals; falls back to plain-text output when `--quiet`, `--debug`, `TERM=dumb`, or non-TTY. |
| `vdpi launcher` | - | Open the interactive Control Center TUI even if a `run-directly` preference was previously saved. |
| `vdpi install` | - | Install `vdpi` into its standard OS location, register automatic background startup (Windows Service / macOS `LaunchAgent` or `LaunchDaemon` / Linux `systemd`), and configure OS integration. |
| `vdpi uninstall [--purge]` | - | Stop the background service, remove installed files and startup registration, and restore OS proxy, routing, and DNS settings. Pass `--purge` to also remove persisted `config.toml`, logs, and `adaptive-cache.json`. |
| `vdpi pause` | `stop` | Temporarily stop the background service and restore OS proxy/routing settings without uninstalling files or service registration. |
| `vdpi resume` | - | Start a paused background service and re-enable anti-DPI protection. |
| `vdpi engine [tun\|proxy]` | - | Display the active desktop engine mode, or switch the persisted default engine between `tun` (transparent virtual adapter) and `proxy` (local HTTP/SOCKS5 proxy). Restarts the installed service when active. |
| `vdpi dns [SERVER]` | - | Display or switch the upstream DNS / RFC 8484 DoH server. Accepts presets (`cloudflare`, `google`, `adguard`, `adguard-unfiltered`, `quad9`, `family`) or any custom IPv4, IPv6, or `https://` DoH URL. Persists to `config.toml` and restarts the active service when running. |
| `vdpi dashboard` | `dash` | Attach the real-time `ratatui` live throughput, connection, and diagnostics dashboard to the running background service without restarting it. |
| `vdpi split [SUBCOMMAND]` | `apps`, `split-tunnel` | Configure per-app split tunneling. Running with no subcommand opens the interactive fuzzy-search app picker TUI. |
| `vdpi config [show\|path\|get\|set\|unset\|validate\|reset]` | - | Inspect, query, modify, validate, or reset `config.toml` (omitting a subcommand defaults to `show`). |
| `vdpi status [--json]` | - | Display live daemon health, active engine mode (TUN or Proxy), Anti-DPI telemetry, background service state, listener/interface details, VPN coexistence status, and OS proxy/DNS state. Pass `--json` for machine-readable JSON output. |
| `vdpi doctor` | - | Run live end-to-end connectivity and DPI bypass diagnostics tailored to the active mode (TUN or Proxy). See [docs/diagnostics.md](./diagnostics.md). |
| `vdpi update` | - | Check GitHub Releases for a newer version, verify the download against `SHA256SUMS.txt`, and upgrade the binary and background service in place. |
| `vdpi help [COMMAND]` | - | Print general usage or detailed help for a specific subcommand. |

### `vdpi dns` Presets and Custom Targets

| Target | Resolved Server | Description |
| :--- | :--- | :--- |
| `cloudflare` | `1.1.1.1` | Fast, privacy-focused public DNS *(default)*. |
| `google` | `8.8.8.8` | Global low-latency public DNS. |
| `adguard` | `94.140.14.14` | Blocks ads, trackers, and phishing domains. |
| `adguard-unfiltered` | `94.140.14.140` | Privacy-focused DNS without ad filtering. |
| `quad9` | `9.9.9.9` | Blocks known malware and phishing domains. |
| `family` | `1.1.1.3` | Cloudflare Family; blocks malware and adult content. |
| `<IPv4 \| IPv6 \| https://...>` | Custom | Any custom IPv4/IPv6 address or RFC 8484 `https://` DoH endpoint URL. |

### `vdpi split` Subcommands

| Subcommand | Description |
| :--- | :--- |
| `vdpi split` | Open the interactive fuzzy-search per-app split-tunneling picker TUI. |
| `vdpi split status [--json]` | Print the active split-tunneling mode (`all`, `exclude`, or `include`) and configured apps (or JSON when `--json` is passed). |
| `vdpi split list [QUERY]` | Discover and list running and installed applications, optionally filtered by a fuzzy search query (also accepts `-f` / `--query` / `--filter`). |
| `vdpi split mode <all\|exclude\|include>` | Set and persist the per-app split-tunneling mode. |
| `vdpi split add <APP>...` | Add one or more executable names or paths to the split-tunnel app list. |
| `vdpi split remove <APP>...` | Remove one or more executable names or paths from the split-tunnel app list. |
| `vdpi split clear` | Clear the configured app list and reset split-tunneling mode to `all`. |

### `vdpi config` Subcommands

| Subcommand | Description |
| :--- | :--- |
| `vdpi config show [--json]` | Print the merged effective configuration as canonical TOML (or JSON when `--json` is passed). |
| `vdpi config path` | Print the resolved `config.toml` path for the current mode. |
| `vdpi config get <KEY>` | Print the effective or configured value for a single configuration key (accepts `snake_case` or `kebab-case`). |
| `vdpi config set <KEY> <VALUE>` | Validate and atomically update a key in `config.toml` (array keys accept TOML arrays or comma-separated values). |
| `vdpi config unset <KEY>` | Remove a key from `config.toml` so it falls back to its built-in default. |
| `vdpi config validate` | Parse `config.toml` and validate bypass/include patterns without starting the engine. |
| `vdpi config reset` | Reset `config.toml` back to built-in defaults (`schema_version = 1`). |

### `vdpi uninstall` Options

| Flag | Description |
| :--- | :--- |
| `--purge` | Also delete persisted configuration (`config.toml`), log files, and `adaptive-cache.json`. |

### `vdpi update` Options

| Flag | Description |
| :--- | :--- |
| `--check` | Check whether a newer release is available without downloading or installing. Conflicts with `--force`. |
| `--force` | Re-download, SHA-256 verify, and reinstall the latest release even if already on the current version. |

---

## Global Options

Global flags can be passed before or after a subcommand. They override both `config.toml` and built-in defaults for the current invocation (and are persisted into service arguments when passed to `vdpi install`).

### Engine and Transport

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--tun` | off | Run in transparent system-wide virtual TUN mode (`Wintun` on Windows, `utun` on macOS, `/dev/net/tun` on Linux). Conflicts with `--proxy`. |
| `--proxy` | on | Run in local HTTP/HTTPS/SOCKS5 proxy mode with OS system proxy integration. Conflicts with `--tun`. |
| `--vpn-coexistence <POLICY>` | `auto-yield` | Behavior when an active full-tunnel third-party VPN (WireGuard, Mullvad, ProtonVPN, OpenVPN, Cloudflare WARP) is detected. Values: `auto-yield`, `warn`, `off`. |
| `--tun-ipv6` | off | Enable IPv6 routing inside the desktop TUN adapter. Disabled by default so IPv4-only networks never blackhole dual-stack hosts. |
| `--no-tun-ipv6` | off | Disable IPv6 routing inside the desktop TUN adapter, overriding `tun_ipv6 = true` in `config.toml`. |

### Anti-DPI and DNS

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-m, --mode <MODE>` | `combo` | Primary DPI desynchronization strategy (alias: `--strategy`). Values: `combo`, `tls-record` (`tlsrec`), `fragment` (`chunk`), `split`. |
| `-c, --chunk-size <BYTES>` | `10` | Segment size in bytes for fragmented TLS `ClientHello` packets (alias: `--window-size`). |
| `--dns <ADDR_OR_URL>` | `1.1.1.1` | Primary upstream DNS / RFC 8484 DoH server IP or URL (alias: `--dns-addr`). |
| `--dns-port <PORT>` | `53` | Port for plain UDP DNS queries when `--no-doh` is set. |
| `-4, --ipv4-only` | off | Resolve IPv4 (`A`) records only (alias: `--dns-ipv4-only`). |
| `--no-ipv4-only` | off | Resolve both IPv4 (`A`) and IPv6 (`AAAA`) records, overriding `ipv4_only = true` in `config.toml`. |
| `--no-doh` | off | Disable RFC 8484 DNS-over-HTTPS and fall back to plain UDP / OS DNS resolution. |
| `--allow-quic` | off | Allow UDP/443 QUIC packets instead of dropping them to force TCP TLS fallback (alias: `--no-block-quic`). |
| `--block-quic` | on | Drop UDP/443 QUIC packets to force TCP TLS fallback, overriding `block_quic = false` in `config.toml`. |
| `--bypass <DOMAIN>` | built-in list | Additional domain, wildcard (e.g. `*.example.com`), CIDR, or IP literal to exclude from DPI desynchronization. Repeatable. |
| `--include <REGEX>` | all non-bypassed | Apply DPI desynchronization only to hostnames matching this regular expression (alias: `--pattern`). Repeatable. |
| `--split-mode <MODE>` | `all` | Per-application split-tunnel routing mode: `all` (protect all apps), `exclude` (bypass listed apps), or `include` (protect only listed apps). |
| `--split-app <APP>` | none | Application executable name or path for per-app split tunneling. Repeatable. |
| `-t, --timeout <MS>` | `0` (`8000`ms) | Outbound TCP connection timeout in milliseconds. `0` uses the default `8000` ms. |

### Proxy Listeners and OS Proxy Integration (Proxy Mode)

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-b, --bind <IP>` | `127.0.0.1` | Local IP address to bind proxy listeners on (alias: `--addr`). |
| `-p, --port <PORT>` | `8080` | Primary proxy port (auto-detects HTTP/1.1, HTTPS `CONNECT`, SOCKS5, and SOCKS4a). |
| `-s, --socks-port <PORT>` | `1080` | Dedicated SOCKS5 (`TCP CONNECT` + `UDP ASSOCIATE`) port. Set to `0` to disable the dedicated listener. |
| `--no-system-proxy` | off | Do not modify OS system proxy settings (WinINET, `networksetup`, GNOME/KDE). |
| `--no-socks-proxy` | off | Legacy compatibility flag (desktop Proxy mode now uses fail-open `/vdpi.pac` rather than OS SOCKS5 system proxy settings; keeps the local SOCKS5 listener active; alias: `--no-socks-system-proxy`). |
| `--no-env-proxy` | off | Do not export `HTTP_PROXY`, `HTTPS_PROXY`, or `NO_PROXY` into the Linux `systemd --user` session environment (Windows and macOS already use fail-open `/vdpi.pac` without proxy env vars; alias: `--no-launchd-env`). |

### Configuration and Logging

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--config <PATH>` | OS default | Load configuration from a custom TOML file instead of the default OS config path. |
| `-q, --quiet` | off | Suppress startup banner and informational output (alias: `--silent`). |
| `-d, --debug` | off | Enable verbose debug logging (disables the foreground TUI dashboard so logs stream cleanly). |
| `-h, --help` | - | Print help information. |
| `-V, --version` | - | Print version information. |

### Desync Modes (`--mode`)

| Value | Behavior |
| :--- | :--- |
| `combo` | Splits TLS `ClientHello` into RFC-compliant TLS records across the SNI midpoint and transmits the initial segments with `TCP_NODELAY`. Feeds into the 7-stage adaptive escalation ladder. |
| `tls-record` | Splits TLS `ClientHello` into separate RFC-compliant TLS records at the SNI midpoint without sub-record TCP chunking. |
| `fragment` | Fragments the entire TLS `ClientHello` into `--chunk-size`-byte TCP segments. |
| `split` | Sends the first `--chunk-size` bytes in an initial TCP segment and the remainder immediately after. |

### VPN Coexistence Policies (`--vpn-coexistence`)

| Value | Behavior |
| :--- | :--- |
| `auto-yield` | Automatically yields TUN routes/DNS (or suspends conflicting proxy rules) while a full-tunnel third-party VPN is active, then recovers automatically after the VPN disconnects. |
| `warn` | Keeps `vdpi` active and surfaces a VPN conflict warning in `vdpi status`, `vdpi doctor`, and the TUI without tearing down automatically. |
| `off` | Disables VPN conflict detection completely. |

---

## Configuration File (`config.toml`)

### Precedence

Settings are resolved in strict order from highest to lowest priority:

```text
CLI flags  >  config.toml  >  built-in defaults
```

When `--config <PATH>` is passed, `vdpi` reads strictly that file instead of the default paths and exits with an error if the file does not exist or cannot be parsed. Missing keys fall back to built-in defaults; CLI flags always win over values in `config.toml`.

### Default Config File Paths and Lookup Order

| Operating System | Per-User Path (Interactive / Foreground) | System / Service Path |
| :--- | :--- | :--- |
| **Windows** | `%LOCALAPPDATA%\vdpi\config.toml` *(fallback: `%USERPROFILE%\AppData\Local\vdpi\config.toml`)* | `%ProgramData%\vdpi\config.toml` (`C:\ProgramData\vdpi\config.toml`) |
| **macOS** | `~/.vdpi/config.toml` | `/Library/Application Support/vdpi/config.toml` |
| **Linux** | `$XDG_CONFIG_HOME/vdpi/config.toml` *(fallback: `~/.config/vdpi/config.toml`)* | `/etc/vdpi/config.toml` |

**Lookup order:**
1. **Explicit `--config <PATH>`:** Always reads `<PATH>` exclusively (errors if missing).
2. **When a system background service is installed:** Uses the **system/service** `config.toml` first across CLI, Control Center, `vdpi config`, `vdpi split`, and service runs so user and service configs never diverge.
3. **Standalone / no system service installed:** Checks the **per-user** path first, then falls back to the **system/service** path, then built-in defaults. On Windows (`LocalSystem` service), **only** `%ProgramData%\vdpi\config.toml` is ever read.

### Schema

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `schema_version` | integer | `1` | Configuration schema version (currently `1`). |
| `engine` | string | `"proxy"` | Desktop transport mode: `"tun"` or `"proxy"`. |
| `mode` | string | `"combo"` | DPI desync mode: `"combo"`, `"tls-record"`, `"fragment"`, or `"split"`. |
| `chunk_size` | integer | `10` | Segment size in bytes for TLS `ClientHello` fragmentation (clamped `>= 1`). |
| `bind` | string (IP) | `"127.0.0.1"` | Local bind address for proxy listeners. |
| `port` | integer | `8080` | Primary HTTP/HTTPS/SOCKS auto-detect proxy port. |
| `socks_port` | integer | `1080` | Dedicated SOCKS5 (TCP + UDP) port (`0` disables the dedicated listener). |
| `dns_addr` | string | `"1.1.1.1"` | Primary upstream DNS or RFC 8484 DoH server IP/URL. |
| `dns_port` | integer | `53` | Plain UDP DNS port when `doh = false`. |
| `doh` | boolean | `true` | Enable RFC 8484 DNS-over-HTTPS ring (`false` equals `--no-doh`). |
| `ipv4_only` | boolean | `false` | Resolve IPv4 (`A`) records only. |
| `block_quic` | boolean | `true` | Drop UDP/443 QUIC packets to force clean TCP TLS fallback (`false` equals `--allow-quic`). |
| `timeout_ms` | integer | `8000` | Outbound TCP connect timeout in milliseconds. |
| `bypass_domains` | array of strings | `[]` | Additional domains, wildcards, CIDRs, or IP literals excluded from DPI fragmentation (appended to built-in LAN/gov/banking defaults). |
| `include_domains` | array of strings | `[]` | Optional hostname regex allowlist; when non-empty, only matching hosts undergo desync. |
| `split_tunnel_mode` | string | `"all"` | Per-app split-tunneling mode: `"all"`, `"exclude"`, or `"include"`. |
| `split_tunnel_apps` | array of strings | `[]` | Executable names or paths matched when `split_tunnel_mode` is `"exclude"` or `"include"`. |
| `system_proxy` | boolean | `true` | Configure OS fail-open `/vdpi.pac` system proxy in Proxy mode (`false` equals `--no-system-proxy`). |
| `socks_system_proxy` | boolean | `true` | Legacy compatibility key (desktop Proxy mode uses fail-open `/vdpi.pac` instead of OS SOCKS5 system proxy entries; `false` equals `--no-socks-proxy`). |
| `env_proxy` | boolean | `true` | Export `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` to the Linux `systemd --user` session environment (ignored on Windows and macOS, which use fail-open `/vdpi.pac`; `false` equals `--no-env-proxy`). |
| `vpn_coexistence` | string | `"auto-yield"` | Third-party full-tunnel VPN policy: `"auto-yield"`, `"warn"`, or `"off"`. |
| `tun_ipv6` | boolean | `false` | Enable IPv6 routing inside the desktop TUN adapter. |

> Note: `-q, --quiet` and `-d, --debug` are **CLI-only** logging flags and are not part of the `config.toml` schema (unknown keys in `config.toml` are ignored for forward compatibility).

### Example `config.toml`

```toml
schema_version = 1

# Transport engine: "tun" (transparent system-wide adapter) or "proxy" (local HTTP/SOCKS5)
engine = "tun"

# Anti-DPI engine settings
mode = "combo"
chunk_size = 10
block_quic = true
timeout_ms = 8000

# DNS settings (RFC 8484 DoH enabled by default)
dns_addr = "1.1.1.1"
dns_port = 53
doh = true
ipv4_only = false

# TUN-specific settings
vpn_coexistence = "auto-yield"
tun_ipv6 = false

# Proxy-mode listener and OS proxy integration settings
bind = "127.0.0.1"
port = 8080
socks_port = 1080
system_proxy = true
socks_system_proxy = true
env_proxy = true

# Optional domain / CIDR filtering
# Built-in LAN, government, and banking bypass rules are always active.
bypass_domains = [
  "*.corp.internal",
  "banking.example.com",
]
include_domains = []

# Per-app split tunneling: "all" (default), "exclude", or "include"
split_tunnel_mode = "all"
split_tunnel_apps = []
```

---

## Common CLI Examples

```bash
# Start transparently in TUN mode for the current session
vdpi --tun start

# Start in Proxy mode on custom ports without touching OS proxy settings
vdpi --proxy --port 8888 --socks-port 1088 --no-system-proxy start

# Switch the installed desktop service to TUN mode
vdpi engine tun

# Switch upstream DNS / DoH to AdGuard or a custom DoH endpoint
vdpi dns adguard
vdpi dns https://dns.quad9.net/dns-query

# Attach the live telemetry dashboard to a running background service
vdpi dashboard

# Exclude specific apps from anti-DPI desync and inspect JSON status
vdpi split mode exclude
vdpi split add steam.exe obs64.exe
vdpi split status --json

# Machine-readable daemon and config inspection
vdpi status --json
vdpi config show --json

# Use a custom config file and run diagnostics
vdpi --config ./custom-vdpi.toml doctor

# Pause and later resume the background service
vdpi pause
vdpi resume

# Check for updates without installing, or force-reinstall the latest release
vdpi update --check
vdpi update --force
```
