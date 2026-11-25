# Security Policy

## Supported Versions

Only the current minor release line receives security fixes.

| Version | Supported |
| :--- | :--- |
| `0.5.x` | Yes |
| `< 0.5.0` | No |

## Reporting a Vulnerability

Do not open public GitHub issues for security vulnerabilities.

Report vulnerabilities privately through GitHub Security Advisories:

https://github.com/Vuln-Inc/vdpi/security/advisories/new

Include:

- Affected platform(s) and `vdpi` version
- Reproduction steps or proof of concept
- Expected impact and any relevant logs or packet captures (redact sensitive data)

## Binary Verification

Every GitHub Release publishes a `SHA256SUMS.txt` manifest covering all desktop and mobile release assets (`vdpi-windows-x86_64.zip`, `vdpi-macos-universal.tar.gz`, `vdpi-linux-x86_64.tar.gz`, `vdpi-linux-arm64.tar.gz`, `vdpi-android-universal.apk`, `vdpi-ios-unsigned.ipa`).

### Manual Verification

Linux:

```sh
sha256sum --ignore-missing -c SHA256SUMS.txt
```

macOS:

```sh
shasum -a 256 --ignore-missing -c SHA256SUMS.txt
```

Windows (PowerShell):

```powershell
Get-FileHash .\vdpi-windows-x86_64.zip -Algorithm SHA256
# Compare the hash output against the matching entry in SHA256SUMS.txt
```

### Automatic Verification (`vdpi update`)

On desktop, `vdpi update` fetches both the target release archive and `SHA256SUMS.txt` from GitHub Releases over HTTPS and verifies the SHA-256 digest before replacing the installed binary. Updates are aborted if the checksum file is missing, unreadable, or does not match the downloaded artifact.

## Privacy and Threat Model

`vdpi` is a local-only anti-DPI engine:

- **Zero telemetry:** `vdpi` collects no analytics, crash reports, usage metrics, or device identifiers.
- **No remote proxy or VPN servers:** All traffic stays on-device. Desktop runs either an on-device userspace TUN adapter (`Wintun` / `utun` / `/dev/net/tun`) or a local loopback proxy (`127.0.0.1`); Android (`VpnService`) and iOS (`NEPacketTunnelProvider`) run the same on-device userspace TUN stack. Packets go directly from your device to their destination.
- **No IP masking:** `vdpi` does not hide your IP address or encrypt traffic beyond the protocols your applications already use (such as TLS). It modifies initial transport framing locally to bypass passive/active ISP DPI inspection.
- **External requests:** Outside of your own application traffic, `vdpi` only contacts:
  - Configured RFC 8484 DNS-over-HTTPS (DoH) resolvers for anti-poisoning DNS resolution
  - GitHub Releases (`api.github.com` / `github.com`) when running `vdpi update` on desktop or during mobile version checks
