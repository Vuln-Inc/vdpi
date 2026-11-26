//! Linux split-tunnel application discovery (`.desktop` entries + `/proc`
//! running processes) and pure-`/proc` local socket-to-process resolution.

use std::collections::HashSet;
use std::env;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use super::{AppCategory, DiscoveredApp};

/// Maximum recursion depth when scanning XDG `applications/` directories
/// (depth 2 finds both top-level `.desktop` files and one nested subdirectory
/// such as `applications/kde4/` or `applications/wine/`).
const MAX_DESKTOP_SCAN_DEPTH: usize = 2;

/// Standard system directories containing `.desktop` application descriptors.
const SYSTEM_DESKTOP_DIRS: &[&str] = &[
    "/usr/share/applications",
    "/usr/local/share/applications",
    "/var/lib/flatpak/exports/share/applications",
];

/// Suffix appended by the Linux kernel to `/proc/<pid>/exe` symlinks when the
/// underlying binary was unlinked or replaced on disk while running.
const DELETED_EXE_SUFFIX: &str = " (deleted)";

/// Discovers installed Linux desktop applications (via `.desktop` files) and
/// currently running user processes (via `/proc`).
pub(super) fn discover_platform_apps() -> Vec<DiscoveredApp> {
    let mut apps = Vec::new();
    discover_desktop_apps(&mut apps);
    discover_proc_apps(Path::new("/proc"), &mut apps);
    apps
}

/// Resolves the owning executable name for a local `(local_ip, local_port)`
/// TCP or UDP socket using `/proc/net/{tcp,tcp6,udp,udp6}` and
/// `/proc/<pid>/fd/*` without spawning any subprocesses.
pub(super) fn lookup_local_port_process(
    local_ip: IpAddr,
    local_port: u16,
    is_udp: bool,
) -> Option<String> {
    let tables: &[(&str, bool)] = if is_udp {
        &[("/proc/net/udp", false), ("/proc/net/udp6", true)]
    } else {
        &[("/proc/net/tcp", false), ("/proc/net/tcp6", true)]
    };

    let mut exact_inodes = Vec::new();
    let mut wildcard_inodes = Vec::new();

    for &(path, is_ipv6) in tables {
        if let Ok(contents) = fs::read_to_string(path) {
            collect_matching_socket_inodes(
                &contents,
                local_ip,
                local_port,
                is_ipv6,
                &mut exact_inodes,
                &mut wildcard_inodes,
            );
        }
    }

    find_process_by_socket_inodes(Path::new("/proc"), &exact_inodes, &wildcard_inodes)
}

fn is_ignored_app_name(exe_name: &str) -> bool {
    let trimmed = exe_name.trim();
    trimmed.is_empty() || trimmed.eq_ignore_ascii_case("vdpi")
}

fn desktop_application_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut seen = HashSet::new();

    let mut push_unique = |path: PathBuf| {
        if seen.insert(path.clone()) {
            dirs.push(path);
        }
    };

    for dir in SYSTEM_DESKTOP_DIRS {
        push_unique(PathBuf::from(dir));
    }

    if let Some(xdg_data_home) = env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        push_unique(PathBuf::from(xdg_data_home).join("applications"));
    }

    if let Some(home) = env::var_os("HOME").filter(|v| !v.is_empty()) {
        let home_path = PathBuf::from(home);
        push_unique(home_path.join(".local/share/applications"));
        push_unique(home_path.join(".local/share/flatpak/exports/share/applications"));
    }

    dirs
}

fn discover_desktop_apps(out: &mut Vec<DiscoveredApp>) {
    for dir in desktop_application_dirs() {
        scan_desktop_dir(&dir, 0, out);
    }
}

fn scan_desktop_dir(dir: &Path, depth: usize, out: &mut Vec<DiscoveredApp>) {
    if depth > MAX_DESKTOP_SCAN_DEPTH {
        return;
    }

    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };

        // Do not follow directory symlinks to prevent traversal cycles, while
        // still reading symlinked `.desktop` files (e.g., Flatpak exports).
        if file_type.is_dir() {
            if depth < MAX_DESKTOP_SCAN_DEPTH {
                scan_desktop_dir(&path, depth + 1, out);
            }
            continue;
        }

        let is_desktop = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("desktop"));
        if !is_desktop {
            continue;
        }

        if let Ok(content) = fs::read_to_string(&path) {
            if let Some(app) = parse_desktop_entry(&content) {
                out.push(app);
            }
        }
    }
}

/// Parses the `[Desktop Entry]` group of a `.desktop` file into a
/// [`DiscoveredApp`].
fn parse_desktop_entry(content: &str) -> Option<DiscoveredApp> {
    let cleaned = content.strip_prefix('\u{feff}').unwrap_or(content);

    let mut in_desktop_entry = false;
    let mut name: Option<&str> = None;
    let mut exec: Option<&str> = None;
    let mut try_exec: Option<&str> = None;

    for raw_line in cleaned.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            if line == "[Desktop Entry]" {
                in_desktop_entry = true;
                continue;
            }
            if in_desktop_entry {
                break;
            }
            continue;
        }

        if !in_desktop_entry {
            continue;
        }

        let Some((raw_key, raw_val)) = line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        let val = raw_val.trim();

        match key {
            "Type" if !val.is_empty() && !val.eq_ignore_ascii_case("Application") => {
                return None;
            }
            "NoDisplay" | "Hidden" if val.eq_ignore_ascii_case("true") => {
                return None;
            }
            "Name" if name.is_none() && !val.is_empty() => {
                name = Some(val);
            }
            "Exec" if exec.is_none() && !val.is_empty() => {
                exec = Some(val);
            }
            "TryExec" if try_exec.is_none() && !val.is_empty() => {
                try_exec = Some(val);
            }
            _ => {}
        }
    }

    let (exe_name, path) = exec
        .and_then(parse_desktop_exec)
        .or_else(|| try_exec.and_then(parse_desktop_exec))?;

    if is_ignored_app_name(&exe_name) {
        return None;
    }

    let display_name = name.unwrap_or(exe_name.as_str()).to_string();

    Some(DiscoveredApp {
        display_name,
        exe_name,
        path,
        is_running: false,
        category: AppCategory::Installed,
    })
}

/// Extracts `(exe_basename, optional_full_path)` from a `.desktop` `Exec=`
/// command line, stripping Desktop Entry field codes (`%u`, `%U`, `%f`, etc.),
/// leading `KEY=VAL` assignments, and `env` wrapper prefixes.
fn parse_desktop_exec(exec: &str) -> Option<(String, Option<String>)> {
    let tokens = tokenize_desktop_exec(exec);
    let mut idx = 0;
    let mut in_env = false;
    let mut env_end_of_opts = false;

    while idx < tokens.len() {
        let tok = tokens[idx].trim();
        idx += 1;

        if tok.is_empty() || is_desktop_field_code(tok) {
            continue;
        }

        if in_env {
            if !env_end_of_opts {
                if tok == "--" {
                    env_end_of_opts = true;
                    continue;
                }
                if env_flag_takes_value(tok) {
                    // Consume the flag's argument token (e.g., `env -u VAR`).
                    idx = idx.saturating_add(1);
                    continue;
                }
                if tok.starts_with('-') && tok.len() > 1 {
                    continue;
                }
            }
            if is_env_assignment(tok) {
                continue;
            }
        } else if is_env_assignment(tok) {
            continue;
        }

        if is_env_wrapper(tok) {
            in_env = true;
            env_end_of_opts = false;
            continue;
        }

        let cleaned = strip_trailing_field_code(tok).trim();
        let exe_name = extract_exe_basename(cleaned)?;
        let full_path = if cleaned.contains('/') {
            Some(cleaned.to_string())
        } else {
            None
        };
        return Some((exe_name, full_path));
    }

    None
}

/// Splits a `.desktop` `Exec=` value into shell-like arguments, handling single
/// quotes, double quotes, and backslash escapes.
fn tokenize_desktop_exec(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut has_token = false;

    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                current.push(ch);
            }
            continue;
        }

        if in_double {
            match ch {
                '"' => in_double = false,
                '\\' => {
                    if let Some(next) = chars.next() {
                        current.push(next);
                    }
                }
                _ => current.push(ch),
            }
            continue;
        }

        match ch {
            '\'' => {
                in_single = true;
                has_token = true;
            }
            '"' => {
                in_double = true;
                has_token = true;
            }
            '\\' => {
                has_token = true;
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            c if c.is_ascii_whitespace() => {
                if has_token {
                    tokens.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            c => {
                current.push(c);
                has_token = true;
            }
        }
    }

    if has_token {
        tokens.push(current);
    }

    tokens
}

fn is_desktop_field_code(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() == 2 && bytes[0] == b'%' && bytes[1].is_ascii_alphabetic()
}

fn strip_trailing_field_code(token: &str) -> &str {
    let bytes = token.as_bytes();
    if bytes.len() > 2
        && bytes[bytes.len() - 2] == b'%'
        && bytes[bytes.len() - 1].is_ascii_alphabetic()
    {
        &token[..bytes.len() - 2]
    } else {
        token
    }
}

fn is_env_wrapper(token: &str) -> bool {
    extract_exe_basename(token).is_some_and(|base| base == "env")
}

fn env_flag_takes_value(flag: &str) -> bool {
    matches!(flag, "-u" | "--unset" | "-C" | "--chdir" | "-P")
}

fn is_env_assignment(token: &str) -> bool {
    let Some((key, _val)) = token.split_once('=') else {
        return false;
    };
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn extract_exe_basename(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.ends_with('/') {
        return None;
    }

    let base = trimmed.rsplit('/').next().unwrap_or(trimmed).trim();
    if base.is_empty() || base == "." || base == ".." || base.contains('\0') {
        return None;
    }

    Some(base.to_string())
}

fn is_pid_dir_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit())
}

fn clean_exe_link_path(link: &Path) -> Option<String> {
    let raw = link.to_str()?.trim();
    let stripped = raw.strip_suffix(DELETED_EXE_SUFFIX).unwrap_or(raw).trim();
    if stripped.is_empty() {
        None
    } else {
        Some(stripped.to_string())
    }
}

/// Resolves `(exe_name, optional_exe_path)` for a `/proc/<pid>` directory.
///
/// Prefers the basename of `/proc/<pid>/exe` (avoiding the Linux kernel's
/// 15-byte `TASK_COMM_LEN` truncation of `/proc/<pid>/comm`), falling back to
/// `/proc/<pid>/comm` when `/proc/<pid>/exe` cannot be read.
fn resolve_pid_process(pid_dir: &Path) -> Option<(String, Option<String>)> {
    if let Ok(link) = fs::read_link(pid_dir.join("exe")) {
        if let Some(cleaned_path) = clean_exe_link_path(&link) {
            if let Some(base) = extract_exe_basename(&cleaned_path) {
                return Some((base, Some(cleaned_path)));
            }
        }
    }

    let comm = fs::read_to_string(pid_dir.join("comm")).ok()?;
    let trimmed = comm.trim();
    if trimmed.is_empty() || trimmed.contains('/') || trimmed.contains('\0') {
        return None;
    }
    Some((trimmed.to_string(), None))
}

fn discover_proc_apps(proc_root: &Path, out: &mut Vec<DiscoveredApp>) {
    let Ok(entries) = fs::read_dir(proc_root) else {
        return;
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name_str) = file_name.to_str() else {
            continue;
        };
        if !is_pid_dir_name(name_str) {
            continue;
        }

        let pid_dir = entry.path();

        // Kernel threads and zombie processes have an empty `/proc/<pid>/cmdline`.
        let Ok(cmdline) = fs::read(pid_dir.join("cmdline")) else {
            continue;
        };
        if cmdline.is_empty() {
            continue;
        }

        let Some((exe_name, exe_path)) = resolve_pid_process(&pid_dir) else {
            continue;
        };
        if is_ignored_app_name(&exe_name) {
            continue;
        }

        // Also skip if `/proc/<pid>/comm` identifies this process as `vdpi`
        // (e.g., when invoked via a symlink or renamed wrapper).
        if let Ok(comm) = fs::read_to_string(pid_dir.join("comm")) {
            if is_ignored_app_name(&comm) {
                continue;
            }
        }

        out.push(DiscoveredApp {
            display_name: exe_name.clone(),
            exe_name,
            path: exe_path,
            is_running: true,
            category: AppCategory::Running,
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpMatchKind {
    Exact,
    Wildcard,
}

fn ip_match_kind(socket_ip: IpAddr, target_ip: IpAddr) -> Option<IpMatchKind> {
    let sock = socket_ip.to_canonical();
    let target = target_ip.to_canonical();
    if sock == target {
        return Some(IpMatchKind::Exact);
    }

    match (sock, target) {
        (IpAddr::V4(s), IpAddr::V4(_)) if s.is_unspecified() => Some(IpMatchKind::Wildcard),
        // Dual-stack IPv6 sockets bound to `::` carry both IPv6 and IPv4 traffic on Linux.
        (IpAddr::V6(s), _) if s.is_unspecified() => Some(IpMatchKind::Wildcard),
        _ => None,
    }
}

/// Parses an 8-hex-digit IPv4 address from `/proc/net/{tcp,udp}`.
///
/// Linux prints the raw `__be32` word with `%08X` in host byte order, so
/// `u32::to_ne_bytes()` recovers the original network-order IPv4 octets on both
/// little-endian and big-endian architectures.
fn parse_proc_net_ipv4(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 || !hex.is_ascii() {
        return None;
    }
    let word = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(word.to_ne_bytes()))
}

/// Parses a 32-hex-digit IPv6 address from `/proc/net/{tcp6,udp6}`.
///
/// Linux prints IPv6 addresses as four consecutive 32-bit host-endian words
/// (`%08X%08X%08X%08X`), not a single 128-bit integer.
fn parse_proc_net_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 || !hex.is_ascii() {
        return None;
    }
    let mut octets = [0u8; 16];
    for idx in 0..4 {
        let word = u32::from_str_radix(&hex[idx * 8..(idx + 1) * 8], 16).ok()?;
        octets[idx * 4..(idx + 1) * 4].copy_from_slice(&word.to_ne_bytes());
    }
    Some(Ipv6Addr::from(octets))
}

fn parse_proc_net_local_addr(field: &str, is_ipv6: bool) -> Option<(IpAddr, u16)> {
    let (ip_hex, port_hex) = field.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if is_ipv6 {
        IpAddr::V6(parse_proc_net_ipv6(ip_hex)?)
    } else {
        IpAddr::V4(parse_proc_net_ipv4(ip_hex)?)
    };
    Some((ip, port))
}

/// Scans a `/proc/net/{tcp,tcp6,udp,udp6}` table for sockets matching
/// `(target_ip, target_port)` and appends their non-zero socket inodes into
/// `exact` (exact IP match) or `wildcard` (`0.0.0.0` / `::` bind fallback).
fn collect_matching_socket_inodes(
    table: &str,
    target_ip: IpAddr,
    target_port: u16,
    is_ipv6: bool,
    exact: &mut Vec<u64>,
    wildcard: &mut Vec<u64>,
) {
    for line in table.lines().skip(1) {
        let mut cols = line.split_ascii_whitespace();
        let Some(_sl) = cols.next() else {
            continue;
        };
        let Some(local_addr) = cols.next() else {
            continue;
        };

        // Fast path: check hex port before parsing IP address or walking
        // remaining columns.
        let Some((_ip_hex, port_hex)) = local_addr.split_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        if port != target_port {
            continue;
        }

        // Column 9 (0-indexed) is `inode`: after consuming cols 0 and 1,
        // `nth(7)` advances across cols 2..=8 and yields col 9.
        let Some(inode_str) = cols.nth(7) else {
            continue;
        };
        let Ok(inode) = inode_str.parse::<u64>() else {
            continue;
        };
        if inode == 0 {
            continue;
        }

        let Some((socket_ip, _)) = parse_proc_net_local_addr(local_addr, is_ipv6) else {
            continue;
        };

        match ip_match_kind(socket_ip, target_ip) {
            Some(IpMatchKind::Exact) if !exact.contains(&inode) => {
                exact.push(inode);
            }
            Some(IpMatchKind::Wildcard) if !wildcard.contains(&inode) => {
                wildcard.push(inode);
            }
            _ => {}
        }
    }
}

fn parse_socket_inode_link(target: &Path) -> Option<u64> {
    target
        .to_str()?
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse::<u64>()
        .ok()
}

fn find_process_by_socket_inodes(
    proc_root: &Path,
    exact: &[u64],
    wildcard: &[u64],
) -> Option<String> {
    if exact.is_empty() && wildcard.is_empty() {
        return None;
    }

    let entries = fs::read_dir(proc_root).ok()?;
    let mut wildcard_match: Option<String> = None;

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name_str) = file_name.to_str() else {
            continue;
        };
        if !is_pid_dir_name(name_str) {
            continue;
        }

        let pid_dir = entry.path();
        let Ok(fd_entries) = fs::read_dir(pid_dir.join("fd")) else {
            continue;
        };

        for fd_entry in fd_entries.flatten() {
            let Ok(target) = fs::read_link(fd_entry.path()) else {
                continue;
            };
            let Some(inode) = parse_socket_inode_link(&target) else {
                continue;
            };

            if exact.contains(&inode) {
                if let Some((exe_name, _)) = resolve_pid_process(&pid_dir) {
                    return Some(exe_name);
                }
            } else if wildcard.contains(&inode) && wildcard_match.is_none() {
                if let Some((exe_name, _)) = resolve_pid_process(&pid_dir) {
                    if exact.is_empty() {
                        return Some(exe_name);
                    }
                    wildcard_match = Some(exe_name);
                }
            }
        }
    }

    wildcard_match
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn encode_proc_ipv4(ip: Ipv4Addr) -> String {
        let word = u32::from_ne_bytes(ip.octets());
        format!("{word:08X}")
    }

    fn encode_proc_ipv6(ip: Ipv6Addr) -> String {
        let octets = ip.octets();
        let mut out = String::with_capacity(32);
        for idx in 0..4 {
            let chunk: [u8; 4] = octets[idx * 4..(idx + 1) * 4].try_into().unwrap();
            let word = u32::from_ne_bytes(chunk);
            out.push_str(&format!("{word:08X}"));
        }
        out
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let seq = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = env::temp_dir().join(format!(
            "vdpi-linux-split-{prefix}-{}-{seq}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn parse_desktop_exec_handles_field_codes_quotes_and_env_prefixes() {
        assert_eq!(
            parse_desktop_exec("/usr/bin/firefox %u"),
            Some(("firefox".to_string(), Some("/usr/bin/firefox".to_string())))
        );
        assert_eq!(
            parse_desktop_exec("discord %U"),
            Some(("discord".to_string(), None))
        );
        assert_eq!(
            parse_desktop_exec(
                "\"/opt/google/chrome/google-chrome\" --profile-directory=Default %U"
            ),
            Some((
                "google-chrome".to_string(),
                Some("/opt/google/chrome/google-chrome".to_string())
            ))
        );
        assert_eq!(
            parse_desktop_exec("\"/opt/My App/my-app\" %F"),
            Some(("my-app".to_string(), Some("/opt/My App/my-app".to_string())))
        );
        assert_eq!(
            parse_desktop_exec(r"/opt/My\ App/launcher %f"),
            Some((
                "launcher".to_string(),
                Some("/opt/My App/launcher".to_string())
            ))
        );
        assert_eq!(
            parse_desktop_exec(
                "env BAMF_DESKTOP_FILE_HINT=/var/lib/snapd/desktop/applications/slack_slack.desktop /snap/bin/slack %U"
            ),
            Some(("slack".to_string(), Some("/snap/bin/slack".to_string())))
        );
        assert_eq!(
            parse_desktop_exec(
                "/usr/bin/env -u WAYLAND_DISPLAY -i MESA_LOADER=zink /usr/bin/steam steam://open/main"
            ),
            Some(("steam".to_string(), Some("/usr/bin/steam".to_string())))
        );
        assert_eq!(
            parse_desktop_exec("env \"FOO=bar baz\" /usr/bin/obs"),
            Some(("obs".to_string(), Some("/usr/bin/obs".to_string())))
        );
        assert_eq!(
            parse_desktop_exec("SDL_VIDEODRIVER=x11 /usr/local/bin/game-client %f"),
            Some((
                "game-client".to_string(),
                Some("/usr/local/bin/game-client".to_string())
            ))
        );
        assert_eq!(parse_desktop_exec("%u %F"), None);
        assert_eq!(parse_desktop_exec("   "), None);
        assert_eq!(parse_desktop_exec("env FOO=bar"), None);
    }

    #[test]
    fn parse_desktop_entry_respects_section_visibility_and_type() {
        let firefox_desktop = "\
[Desktop Entry]
Type=Application
Name=Mozilla Firefox
Name[tr]=Mozilla Firefox TR
Exec=/usr/bin/firefox %u
NoDisplay=false

[Desktop Action new-window]
Name=Open a New Window
Exec=/usr/bin/firefox --new-window
";
        let parsed = parse_desktop_entry(firefox_desktop).expect("valid desktop entry");
        assert_eq!(parsed.display_name, "Mozilla Firefox");
        assert_eq!(parsed.exe_name, "firefox");
        assert_eq!(parsed.path.as_deref(), Some("/usr/bin/firefox"));
        assert!(!parsed.is_running);
        assert_eq!(parsed.category, AppCategory::Installed);

        let no_display = "\
[Desktop Entry]
Type=Application
Name=Helper
Exec=/usr/bin/helper
NoDisplay=true
";
        assert!(parse_desktop_entry(no_display).is_none());

        let hidden = "\
[Desktop Entry]
Type=Application
Name=Old App
Exec=/usr/bin/oldapp
Hidden=true
";
        assert!(parse_desktop_entry(hidden).is_none());

        let link_entry = "\
[Desktop Entry]
Type=Link
Name=Docs
Exec=/usr/bin/xdg-open https://example.com
";
        assert!(parse_desktop_entry(link_entry).is_none());

        let vdpi_entry = "\
[Desktop Entry]
Type=Application
Name=vdpi
Exec=/usr/local/bin/vdpi
";
        assert!(parse_desktop_entry(vdpi_entry).is_none());
    }

    #[test]
    fn proc_net_tcp_ipv4_hex_port_to_inode_parsing() {
        let loopback_hex = encode_proc_ipv4(Ipv4Addr::new(127, 0, 0, 1));
        let lan_hex = encode_proc_ipv4(Ipv4Addr::new(192, 168, 1, 42));
        let any_hex = encode_proc_ipv4(Ipv4Addr::UNSPECIFIED);

        let table = format!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
               0: {loopback_hex}:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 20541 1 0000000000000000 100 0 0 10 0\n\
               1: {lan_hex}:D431 01010101:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 98765 1 0000000000000000 20 4 0 10 -1\n\
               2: {lan_hex}:D431 08080808:01BB 06 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000\n\
               3: {any_hex}:D431 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 55555 1 0000000000000000\n"
        );

        let mut exact = Vec::new();
        let mut wildcard = Vec::new();
        collect_matching_socket_inodes(
            &table,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)),
            54321,
            false,
            &mut exact,
            &mut wildcard,
        );
        // Inode 0 (TIME_WAIT) is ignored; exact match and wildcard fallback are separated.
        assert_eq!(exact, vec![98765]);
        assert_eq!(wildcard, vec![55555]);

        // Unmatched port yields nothing.
        let mut exact_none = Vec::new();
        let mut wildcard_none = Vec::new();
        collect_matching_socket_inodes(
            &table,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            443,
            false,
            &mut exact_none,
            &mut wildcard_none,
        );
        assert!(exact_none.is_empty());
        assert!(wildcard_none.is_empty());

        // IPv4 0.0.0.0 wildcard must NOT match a pure IPv6 lookup.
        let mut exact_v6 = Vec::new();
        let mut wildcard_v6 = Vec::new();
        collect_matching_socket_inodes(
            &table,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            54321,
            false,
            &mut exact_v6,
            &mut wildcard_v6,
        );
        assert!(exact_v6.is_empty());
        assert!(wildcard_v6.is_empty());
    }

    #[test]
    fn proc_net_tcp6_ipv6_and_dual_stack_hex_parsing() {
        let v6_loopback = encode_proc_ipv6(Ipv6Addr::LOCALHOST);
        let v4_mapped = encode_proc_ipv6(Ipv4Addr::new(192, 168, 1, 42).to_ipv6_mapped());
        let v6_any = encode_proc_ipv6(Ipv6Addr::UNSPECIFIED);

        let table = format!(
            "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
               0: {v6_loopback}:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 31415 1 0000000000000000\n\
               1: {v4_mapped}:C350 0000000000000000FFFF000001010101:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 42424 1 0000000000000000\n\
               2: {v6_any}:14E9 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 77777 2 0000000000000000\n"
        );

        let mut exact = Vec::new();
        let mut wildcard = Vec::new();
        collect_matching_socket_inodes(
            &table,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            443,
            true,
            &mut exact,
            &mut wildcard,
        );
        assert_eq!(exact, vec![31415]);
        assert!(wildcard.is_empty());

        // IPv4 target matches dual-stack IPv4-mapped IPv6 entry as exact.
        let mut exact_mapped = Vec::new();
        let mut wildcard_mapped = Vec::new();
        collect_matching_socket_inodes(
            &table,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)),
            50000,
            true,
            &mut exact_mapped,
            &mut wildcard_mapped,
        );
        assert_eq!(exact_mapped, vec![42424]);
        assert!(wildcard_mapped.is_empty());

        // Dual-stack `::` UDP socket matches IPv4 target as wildcard.
        let mut exact_wild = Vec::new();
        let mut wildcard_wild = Vec::new();
        collect_matching_socket_inodes(
            &table,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            5353,
            true,
            &mut exact_wild,
            &mut wildcard_wild,
        );
        assert!(exact_wild.is_empty());
        assert_eq!(wildcard_wild, vec![77777]);
    }

    #[test]
    fn socket_inode_link_and_deleted_exe_helpers() {
        assert_eq!(
            parse_socket_inode_link(Path::new("socket:[98765]")),
            Some(98765)
        );
        assert_eq!(parse_socket_inode_link(Path::new("pipe:[12345]")), None);
        assert_eq!(parse_socket_inode_link(Path::new("/dev/null")), None);

        assert_eq!(
            clean_exe_link_path(Path::new("/usr/lib/firefox/firefox (deleted)")),
            Some("/usr/lib/firefox/firefox".to_string())
        );
        assert_eq!(
            clean_exe_link_path(Path::new("/usr/bin/discord")),
            Some("/usr/bin/discord".to_string())
        );
    }

    #[test]
    fn discover_proc_apps_skips_kernel_threads_and_vdpi() {
        let proc_root = unique_temp_dir("proc");

        // Kernel thread: empty cmdline -> skipped.
        let kthread = proc_root.join("2");
        fs::create_dir_all(&kthread).unwrap();
        fs::write(kthread.join("cmdline"), b"").unwrap();
        fs::write(kthread.join("comm"), "kthreadd\n").unwrap();

        // vdpi process -> skipped.
        let vdpi_pid = proc_root.join("100");
        fs::create_dir_all(&vdpi_pid).unwrap();
        fs::write(vdpi_pid.join("cmdline"), b"/usr/local/bin/vdpi\0").unwrap();
        fs::write(vdpi_pid.join("comm"), "vdpi\n").unwrap();

        // Normal user process (falling back to `comm` when `exe` symlink is absent).
        let firefox_pid = proc_root.join("200");
        fs::create_dir_all(&firefox_pid).unwrap();
        fs::write(firefox_pid.join("cmdline"), b"/usr/bin/firefox\0").unwrap();
        fs::write(firefox_pid.join("comm"), "firefox\n").unwrap();

        // Non-PID entry -> ignored.
        fs::create_dir_all(proc_root.join("net")).unwrap();

        let mut apps = Vec::new();
        discover_proc_apps(&proc_root, &mut apps);

        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].exe_name, "firefox");
        assert_eq!(apps[0].display_name, "firefox");
        assert!(apps[0].is_running);
        assert_eq!(apps[0].category, AppCategory::Running);

        let _ = fs::remove_dir_all(&proc_root);
    }

    #[test]
    fn scan_desktop_dir_reads_valid_entries_and_ignores_non_desktop_files() {
        let apps_dir = unique_temp_dir("desktop");
        let sub_dir = apps_dir.join("kde4");
        fs::create_dir_all(&sub_dir).unwrap();

        fs::write(
            apps_dir.join("discord.desktop"),
            "[Desktop Entry]\nType=Application\nName=Discord\nExec=env XDG_SESSION_TYPE=x11 /usr/bin/discord %U\n",
        )
        .unwrap();
        fs::write(
            sub_dir.join("obs.desktop"),
            "[Desktop Entry]\nType=Application\nName=OBS Studio\nExec=/usr/bin/obs\n",
        )
        .unwrap();
        fs::write(apps_dir.join("README.txt"), "not a desktop file").unwrap();

        let mut apps = Vec::new();
        scan_desktop_dir(&apps_dir, 0, &mut apps);
        apps.sort_by(|a, b| a.exe_name.cmp(&b.exe_name));

        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].exe_name, "discord");
        assert_eq!(apps[0].display_name, "Discord");
        assert_eq!(apps[1].exe_name, "obs");
        assert_eq!(apps[1].display_name, "OBS Studio");

        let _ = fs::remove_dir_all(&apps_dir);
    }
}
