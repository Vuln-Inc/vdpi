//! Linux split-tunnel application discovery (`.desktop` entries + `/proc`
//! running processes) and pure-`/proc` local socket-to-process resolution.

use std::collections::HashSet;
use std::env;
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

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
    "/var/lib/snapd/desktop/applications",
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
    let lower = exe_name.trim().to_ascii_lowercase();
    lower.is_empty() || lower == "vdpi" || lower.starts_with("vdpi-desktop")
}

fn is_sandbox_or_helper_daemon(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "bwrap"
            | "xdg-dbus-proxy"
            | "flatpak-session-helper"
            | "flatpak-portal"
            | "flatpak-dbus-proxy"
    ) || lower.starts_with("zypak-")
}

fn is_valid_non_root_username(username: &str) -> bool {
    !username.is_empty()
        && username != "root"
        && !username.contains(':')
        && !username.contains('/')
        && !username.contains('\0')
}

fn resolve_user_home_from_passwd(passwd: &str, username: &str) -> Option<PathBuf> {
    if !is_valid_non_root_username(username) {
        return None;
    }

    for line in passwd.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut fields = trimmed.split(':');
        let Some(user) = fields.next() else {
            continue;
        };
        if user != username {
            continue;
        }
        // Fields: user:passwd:uid:gid:gecos:home:shell
        let Some(home) = fields.nth(4) else {
            continue;
        };
        let home_trimmed = home.trim();
        if home_trimmed.starts_with('/') && !home_trimmed.is_empty() {
            return Some(PathBuf::from(home_trimmed));
        }
    }
    None
}

fn resolve_user_home_via_getpwnam(username: &str) -> Option<PathBuf> {
    if !is_valid_non_root_username(username) {
        return None;
    }

    let c_name = CString::new(username).ok()?;
    let mut buf_size = match unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) } {
        n if n > 0 => (n as usize).clamp(1024, 65_536),
        _ => 4096,
    };
    const MAX_BUF_SIZE: usize = 1024 * 1024;
    let mut eintr_retries = 0u8;

    loop {
        let mut pwd = MaybeUninit::<libc::passwd>::zeroed();
        let mut result: *mut libc::passwd = ptr::null_mut();
        let mut buf = vec![0u8; buf_size];

        let ret = unsafe {
            libc::getpwnam_r(
                c_name.as_ptr(),
                pwd.as_mut_ptr(),
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &mut result,
            )
        };

        if ret == 0 {
            if result.is_null() {
                return None;
            }
            let pw = unsafe { &*result };
            if pw.pw_dir.is_null() {
                return None;
            }
            let dir_bytes = unsafe { CStr::from_ptr(pw.pw_dir as *const libc::c_char) }.to_bytes();
            if dir_bytes.is_empty() || dir_bytes[0] != b'/' {
                return None;
            }
            return Some(PathBuf::from(OsStr::from_bytes(dir_bytes)));
        }

        if ret == libc::EINTR && eintr_retries < 3 {
            eintr_retries += 1;
            continue;
        }

        if ret == libc::ERANGE && buf_size < MAX_BUF_SIZE {
            buf_size = buf_size.saturating_mul(2).min(MAX_BUF_SIZE);
            continue;
        }

        return None;
    }
}

fn resolve_sudo_user_home() -> Option<PathBuf> {
    let sudo_user = env::var("SUDO_USER").ok()?;
    let username = sudo_user.trim();
    if !is_valid_non_root_username(username) {
        return None;
    }

    if let Some(home) = resolve_user_home_via_getpwnam(username) {
        return Some(home);
    }

    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        if let Some(home) = resolve_user_home_from_passwd(&passwd, username) {
            return Some(home);
        }
    }

    let fallback = PathBuf::from("/home").join(username);
    fallback.is_dir().then_some(fallback)
}

fn desktop_application_dirs_from(
    xdg_data_dirs: Option<&OsStr>,
    xdg_data_home: Option<&OsStr>,
    home: Option<&OsStr>,
    sudo_home: Option<PathBuf>,
) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut seen = HashSet::new();

    let mut push_unique = |path: PathBuf| {
        if seen.insert(path.clone()) {
            dirs.push(path);
        }
    };

    if let Some(data_dirs) = xdg_data_dirs.filter(|v| !v.is_empty()) {
        for base in env::split_paths(data_dirs) {
            if base.is_absolute() {
                push_unique(base.join("applications"));
            }
        }
    }

    for dir in SYSTEM_DESKTOP_DIRS {
        push_unique(PathBuf::from(dir));
    }

    if let Some(xdg_data_home) = xdg_data_home.filter(|v| !v.is_empty()) {
        let base = PathBuf::from(xdg_data_home);
        if base.is_absolute() {
            push_unique(base.join("applications"));
        }
    }

    if let Some(home) = home.filter(|v| !v.is_empty()) {
        let home_path = PathBuf::from(home);
        push_unique(home_path.join(".local/share/applications"));
        push_unique(home_path.join(".local/share/flatpak/exports/share/applications"));
    }

    if let Some(sudo_home) = sudo_home {
        push_unique(sudo_home.join(".local/share/applications"));
        push_unique(sudo_home.join(".local/share/flatpak/exports/share/applications"));
    }

    dirs
}

fn desktop_application_dirs() -> Vec<PathBuf> {
    let xdg_data_dirs = env::var_os("XDG_DATA_DIRS");
    let xdg_data_home = env::var_os("XDG_DATA_HOME");
    let home = env::var_os("HOME");
    desktop_application_dirs_from(
        xdg_data_dirs.as_deref(),
        xdg_data_home.as_deref(),
        home.as_deref(),
        resolve_sudo_user_home(),
    )
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
    let mut x_flatpak: Option<&str> = None;

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
            "X-Flatpak" if x_flatpak.is_none() && !val.is_empty() => {
                x_flatpak = Some(val);
            }
            _ => {}
        }
    }

    let exec_parsed = exec
        .and_then(parse_desktop_exec)
        .or_else(|| try_exec.and_then(parse_desktop_exec));

    let (exe_name, path) = if let Some(flatpak_id) = x_flatpak.and_then(sanitize_flatpak_app_id) {
        let path = exec_parsed.and_then(|(_, p)| p);
        (flatpak_id, path)
    } else {
        let (exe, path) = exec_parsed?;
        if exe.eq_ignore_ascii_case("flatpak") {
            return None;
        }
        (exe, path)
    };

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
/// leading `KEY=VAL` assignments, `env` wrapper prefixes, and `flatpak run`
/// wrappers (preferring the Flatpak reverse-DNS app ID so it matches runtime
/// cgroup / `.flatpak-info` resolution, falling back to `--command=CMD`).
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
        if exe_name.eq_ignore_ascii_case("flatpak") {
            return parse_flatpak_run_args(&tokens[idx..]);
        }

        let full_path = if cleaned.contains('/') {
            Some(cleaned.to_string())
        } else {
            None
        };
        return Some((exe_name, full_path));
    }

    None
}

fn sanitize_flatpak_app_id(raw: &str) -> Option<String> {
    let trimmed = strip_trailing_field_code(raw.trim()).trim();
    let without_kind = trimmed.strip_prefix("app/").unwrap_or(trimmed);
    let app_id = without_kind
        .split('/')
        .next()
        .unwrap_or(without_kind)
        .trim();
    if app_id.is_empty()
        || app_id == "."
        || app_id == ".."
        || app_id.contains('\0')
        || app_id.contains('/')
        || app_id.eq_ignore_ascii_case("flatpak")
    {
        return None;
    }
    Some(app_id.to_string())
}

fn is_reverse_dns_flatpak_id(id: &str) -> bool {
    let mut parts = id.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(second) = parts.next() else {
        return false;
    };
    !first.is_empty()
        && !second.is_empty()
        && id.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

fn flatpak_run_flag_takes_value(flag: &str) -> bool {
    matches!(
        flag,
        "--arch"
            | "--branch"
            | "--commit"
            | "--runtime"
            | "--runtime-version"
            | "--runtime-commit"
            | "--cwd"
            | "--env"
            | "--env-fd"
            | "--unset-env"
            | "--filesystem"
            | "--nofilesystem"
            | "--socket"
            | "--nosocket"
            | "--device"
            | "--nodevice"
            | "--share"
            | "--unshare"
            | "--allow"
            | "--disallow"
            | "--talk-name"
            | "--own-name"
            | "--no-talk-name"
            | "--system-talk-name"
            | "--system-own-name"
            | "--system-no-talk-name"
            | "--installation"
            | "--persist"
            | "--app-path"
            | "--usr-path"
            | "--parent-pid"
            | "-p"
    )
}

fn is_generic_flatpak_wrapper_cmd(base: &str) -> bool {
    let lower = base.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "sh" | "bash" | "dash" | "zsh" | "env" | "flatpak" | "bwrap"
    ) || lower.starts_with("zypak-")
}

/// Parses arguments following `flatpak` in a `.desktop` `Exec=` line
/// (`flatpak run [OPTIONS...] [--command=CMD] APP_ID [ARGS...]`).
fn parse_flatpak_run_args(args: &[String]) -> Option<(String, Option<String>)> {
    let mut idx = 0;

    // Skip optional global flags before the `run` subcommand.
    while idx < args.len() {
        let tok = args[idx].trim();
        idx += 1;
        if tok.is_empty() || is_desktop_field_code(tok) {
            continue;
        }
        if tok == "run" {
            break;
        }
        if tok.starts_with('-') {
            if tok == "--installation" {
                idx = idx.saturating_add(1);
            }
            continue;
        }
        // Non-`run` flatpak subcommand (e.g. `flatpak update`).
        return None;
    }

    let mut command_override: Option<String> = None;
    let mut app_id: Option<String> = None;
    let mut fallback_positional: Option<String> = None;

    while idx < args.len() {
        let tok = args[idx].trim();
        idx += 1;
        if tok.is_empty()
            || is_desktop_field_code(tok)
            || matches!(tok, "@@" | "@@u" | "@@U" | "@@f" | "@@F")
        {
            continue;
        }

        if tok == "--" {
            while idx < args.len() {
                let candidate = args[idx].trim();
                idx += 1;
                if candidate.is_empty() || is_desktop_field_code(candidate) {
                    continue;
                }
                if let Some(id) = sanitize_flatpak_app_id(candidate) {
                    app_id = Some(id);
                    break;
                }
            }
            break;
        }

        if let Some(val) = tok.strip_prefix("--command=") {
            if !val.trim().is_empty() {
                command_override = Some(val.trim().to_string());
            }
            continue;
        }

        if tok == "--command" {
            if idx < args.len() {
                let val = args[idx].trim();
                idx += 1;
                if !val.is_empty() {
                    command_override = Some(val.to_string());
                }
            }
            continue;
        }

        if tok.starts_with('-') {
            if !tok.contains('=') && flatpak_run_flag_takes_value(tok) {
                idx = idx.saturating_add(1);
            }
            continue;
        }

        if let Some(id) = sanitize_flatpak_app_id(tok) {
            if is_reverse_dns_flatpak_id(&id) {
                app_id = Some(id);
                break;
            }
            if fallback_positional.is_none() {
                fallback_positional = Some(id);
            }
        }
    }

    let command_info = command_override.and_then(|cmd| {
        let cleaned = strip_trailing_field_code(&cmd).trim();
        let base = extract_exe_basename(cleaned)?;
        if is_generic_flatpak_wrapper_cmd(&base) {
            return None;
        }
        let full_path = cleaned.contains('/').then(|| cleaned.to_string());
        Some((base, full_path))
    });

    if let Some(id) = app_id {
        let full_path = command_info.and_then(|(_, p)| p);
        return Some((id, full_path));
    }

    command_info.or_else(|| fallback_positional.map(|id| (id, None)))
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

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn unescape_systemd_unit_name(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if i + 3 < bytes.len() && bytes[i] == b'\\' && bytes[i + 1] == b'x' {
            if let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 2]), hex_nibble(bytes[i + 3])) {
                out.push((hi << 4) | lo);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (idx, &b) in bytes.iter().enumerate() {
        if matches!(idx, 8 | 13 | 18 | 23) {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn is_flatpak_hex_or_numeric_suffix(s: &str) -> bool {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    // Strip any numeric suffix (e.g. PID `99`, `12345`), any hex suffix
    // containing a digit (e.g. `1a2b`, `abcdef0123456789`, 32-char compact
    // UUIDs), or long all-letter hex suffixes (e.g. `deadbeef`).
    s.bytes().any(|b| b.is_ascii_digit()) || s.len() >= 6
}

fn strip_flatpak_instance_suffix(without_unit: &str) -> &str {
    if let Some((before_at, _)) = without_unit.split_once('@') {
        return before_at;
    }

    // Trailing `-<UUID>` (8-4-4-4-12 hyphenated UUID).
    let bytes = without_unit.as_bytes();
    if bytes.len() > 37 && bytes[bytes.len() - 37] == b'-' {
        if let Some(candidate) = without_unit.get(bytes.len() - 36..) {
            if is_uuid(candidate) {
                return &without_unit[..bytes.len() - 37];
            }
        }
    }

    // Trailing `-<numeric>` or `-<hex>` (including compact 32-char UUIDs).
    if let Some((prefix, suffix)) = without_unit.rsplit_once('-') {
        if !prefix.is_empty() && is_flatpak_hex_or_numeric_suffix(suffix) {
            return prefix;
        }
    }

    without_unit
}

/// Extracts a Flatpak application ID from `/proc/<pid>/cgroup` lines containing
/// a systemd `app-flatpak-<APP_ID>-<instance>.scope` (or `@<instance>.service`) unit,
/// stripping numeric, hex, or UUID instance suffixes.
fn parse_flatpak_cgroup_app_id(cgroup: &str) -> Option<String> {
    const MARKER: &str = "app-flatpak-";

    for line in cgroup.lines() {
        let Some(pos) = line.find(MARKER) else {
            continue;
        };
        let rest = &line[pos + MARKER.len()..];
        let segment = rest
            .split(|c: char| c == '/' || c.is_ascii_whitespace())
            .next()
            .unwrap_or(rest)
            .trim();
        let without_unit = segment
            .strip_suffix(".scope")
            .or_else(|| segment.strip_suffix(".service"))
            .unwrap_or(segment);
        let without_instance = strip_flatpak_instance_suffix(without_unit);
        let decoded = unescape_systemd_unit_name(without_instance);
        if let Some(app_id) = sanitize_flatpak_app_id(&decoded) {
            return Some(app_id);
        }
    }

    None
}

/// Parses the Flatpak application ID from the `[Application]` section (`name=...`)
/// of `/proc/<pid>/root/.flatpak-info` for non-systemd Flatpak sessions.
fn parse_flatpak_info_app_id(content: &str) -> Option<String> {
    let cleaned = content.strip_prefix('\u{feff}').unwrap_or(content);
    let mut in_application = false;

    for raw_line in cleaned.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            if line == "[Application]" {
                in_application = true;
                continue;
            }
            if in_application {
                break;
            }
            continue;
        }

        if !in_application {
            continue;
        }

        let Some((raw_key, raw_val)) = line.split_once('=') else {
            continue;
        };
        if raw_key.trim() == "name" {
            return sanitize_flatpak_app_id(raw_val.trim());
        }
    }

    None
}

/// Extracts a Snap package name from `/proc/<pid>/cgroup` lines containing a
/// systemd `snap.<PACKAGE>.<APP>-<instance>.scope` unit so Snaps whose
/// internal ELF basename differs from their Snap package name (e.g.
/// `chromium` -> `chrome`, `obs-studio` -> `obs`) match their `.desktop` entry.
fn parse_snap_cgroup_package(cgroup: &str) -> Option<String> {
    for line in cgroup.lines() {
        let path = line.splitn(3, ':').nth(2).unwrap_or(line).trim();
        for segment in path.split('/') {
            let segment = segment.trim();
            let Some(rest) = segment.strip_prefix("snap.") else {
                continue;
            };
            let Some(without_scope) = rest.strip_suffix(".scope") else {
                continue;
            };
            let Some((raw_pkg, app_with_instance)) = without_scope.split_once('.') else {
                continue;
            };
            let Some((app, instance)) = app_with_instance.split_once('-') else {
                continue;
            };
            if app.is_empty() || instance.is_empty() {
                continue;
            }
            let decoded = unescape_systemd_unit_name(raw_pkg);
            let pkg = decoded.trim();
            if !pkg.is_empty()
                && pkg != "."
                && pkg != ".."
                && !pkg.contains('/')
                && !pkg.contains('\0')
                && !pkg.chars().any(|c| c.is_ascii_whitespace())
            {
                return Some(pkg.to_string());
            }
        }
    }

    None
}

/// Resolves `(exe_name, optional_exe_path)` for a `/proc/<pid>` directory.
///
/// Inspects `/proc/<pid>/cgroup` for `app-flatpak-` and `snap.<PKG>.<APP>-*.scope`
/// units (with a `/proc/<pid>/root/.flatpak-info` fallback for non-systemd
/// Flatpak sessions) so sandboxed Flatpak and Snap processes match their app
/// ID / package name cleanly; otherwise prefers the basename of `/proc/<pid>/exe`
/// (avoiding the Linux kernel's 15-byte `TASK_COMM_LEN` truncation of
/// `/proc/<pid>/comm`), falling back to `/proc/<pid>/comm`.
fn resolve_pid_process(pid_dir: &Path) -> Option<(String, Option<String>)> {
    let exe_info = fs::read_link(pid_dir.join("exe")).ok().and_then(|link| {
        let cleaned_path = clean_exe_link_path(&link)?;
        let base = extract_exe_basename(&cleaned_path)?;
        Some((base, cleaned_path))
    });

    if let Ok(cgroup) = fs::read_to_string(pid_dir.join("cgroup")) {
        if let Some(flatpak_id) = parse_flatpak_cgroup_app_id(&cgroup) {
            return Some((flatpak_id, exe_info.map(|(_, path)| path)));
        }
        if let Some(snap_pkg) = parse_snap_cgroup_package(&cgroup) {
            return Some((snap_pkg, exe_info.map(|(_, path)| path)));
        }
    }

    if let Ok(flatpak_info) = fs::read_to_string(pid_dir.join("root/.flatpak-info")) {
        if let Some(flatpak_id) = parse_flatpak_info_app_id(&flatpak_info) {
            return Some((flatpak_id, exe_info.map(|(_, path)| path)));
        }
    }

    if let Some((base, cleaned_path)) = exe_info {
        return Some((base, Some(cleaned_path)));
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

        // Skip sandbox/system helper daemons (`bwrap`, `xdg-dbus-proxy`, `zypak-*`)
        // and `vdpi` itself by inspecting raw `exe` and `comm` before cgroup mapping.
        if let Ok(link) = fs::read_link(pid_dir.join("exe")) {
            if let Some(base) = clean_exe_link_path(&link).and_then(|p| extract_exe_basename(&p)) {
                if is_ignored_app_name(&base) || is_sandbox_or_helper_daemon(&base) {
                    continue;
                }
            }
        }
        if let Ok(comm) = fs::read_to_string(pid_dir.join("comm")) {
            if is_ignored_app_name(&comm) || is_sandbox_or_helper_daemon(&comm) {
                continue;
            }
        }

        let Some((exe_name, exe_path)) = resolve_pid_process(&pid_dir) else {
            continue;
        };
        if is_ignored_app_name(&exe_name) || is_sandbox_or_helper_daemon(&exe_name) {
            continue;
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

    #[test]
    fn flatpak_desktop_entries_and_exec_never_collapse_to_flatpak() {
        assert_eq!(
            parse_desktop_exec(
                "/usr/bin/flatpak run --branch=stable --arch=x86_64 --command=discord --file-forwarding com.discordapp.Discord @@u %U @@"
            ),
            Some(("com.discordapp.Discord".to_string(), None))
        );
        assert_eq!(
            parse_desktop_exec(
                "flatpak run --branch=stable --command=/app/bin/firefox org.mozilla.firefox %u"
            ),
            Some((
                "org.mozilla.firefox".to_string(),
                Some("/app/bin/firefox".to_string())
            ))
        );
        assert_eq!(
            parse_desktop_exec("/usr/bin/flatpak run --branch=stable org.vinegarhq.Sober %u"),
            Some(("org.vinegarhq.Sober".to_string(), None))
        );
        assert_eq!(
            parse_desktop_exec("flatpak run --command=sh com.example.WrappedApp"),
            Some(("com.example.WrappedApp".to_string(), None))
        );
        assert_eq!(
            parse_desktop_exec(
                "flatpak run --branch=stable app/com.discordapp.Discord/x86_64/stable %U"
            ),
            Some(("com.discordapp.Discord".to_string(), None))
        );
        assert_eq!(
            parse_desktop_exec(
                "flatpak run --branch=stable --command=discord -- com.discordapp.Discord --start-minimized"
            ),
            Some(("com.discordapp.Discord".to_string(), None))
        );

        let discord_flatpak = "\
[Desktop Entry]
Type=Application
Name=Discord
Exec=/usr/bin/flatpak run --branch=stable --arch=x86_64 --command=discord --file-forwarding com.discordapp.Discord @@u %U @@
X-Flatpak=com.discordapp.Discord
";
        let parsed = parse_desktop_entry(discord_flatpak).expect("flatpak desktop entry");
        assert_eq!(parsed.display_name, "Discord");
        assert_eq!(parsed.exe_name, "com.discordapp.Discord");
        assert_ne!(parsed.exe_name, "flatpak");

        // Without `X-Flatpak=`, `flatpak run ... APP_ID` must still resolve to
        // the reverse-DNS Flatpak app ID rather than `--command` basename.
        let discord_flatpak_without_x_flatpak = "\
[Desktop Entry]
Type=Application
Name=Discord
Exec=/usr/bin/flatpak run --branch=stable --arch=x86_64 --command=discord --file-forwarding com.discordapp.Discord @@u %U @@
";
        let parsed_no_x = parse_desktop_entry(discord_flatpak_without_x_flatpak)
            .expect("flatpak desktop entry without X-Flatpak");
        assert_eq!(parsed_no_x.display_name, "Discord");
        assert_eq!(parsed_no_x.exe_name, "com.discordapp.Discord");

        let sober_flatpak = "\
[Desktop Entry]
Type=Application
Name=Sober
Exec=/usr/bin/flatpak run --branch=stable org.vinegarhq.Sober %u
X-Flatpak=org.vinegarhq.Sober
";
        let sober = parse_desktop_entry(sober_flatpak).expect("sober flatpak entry");
        assert_eq!(sober.display_name, "Sober");
        assert_eq!(sober.exe_name, "org.vinegarhq.Sober");
    }

    #[test]
    fn flatpak_cgroup_hex_uuid_scopes_and_flatpak_info_fallback() {
        assert_eq!(
            parse_flatpak_cgroup_app_id(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.mozilla.firefox-abcdef0123456789.scope\n"
            )
            .as_deref(),
            Some("org.mozilla.firefox")
        );
        assert_eq!(
            parse_flatpak_cgroup_app_id(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.mozilla.firefox-deadbeef.scope\n"
            )
            .as_deref(),
            Some("org.mozilla.firefox")
        );
        assert_eq!(
            parse_flatpak_cgroup_app_id(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.mozilla.firefox-550e8400-e29b-41d4-a716-446655440000.scope\n"
            )
            .as_deref(),
            Some("org.mozilla.firefox")
        );
        assert_eq!(
            parse_flatpak_cgroup_app_id(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.mozilla.firefox-550e8400e29b41d4a716446655440000.scope\n"
            )
            .as_deref(),
            Some("org.mozilla.firefox")
        );
        assert_eq!(
            parse_flatpak_cgroup_app_id(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-io.gitlab.librewolf\\x2dcommunity-550e8400-e29b-41d4-a716-446655440000.scope\n"
            )
            .as_deref(),
            Some("io.gitlab.librewolf-community")
        );
        assert_eq!(
            parse_flatpak_cgroup_app_id(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.mozilla.firefox@550e8400-e29b-41d4-a716-446655440000.service\n"
            )
            .as_deref(),
            Some("org.mozilla.firefox")
        );

        let flatpak_info = "\
[Application]
name=org.mozilla.firefox
runtime=runtime/org.freedesktop.Platform/x86_64/23.08

[Instance]
name=ignored.instance.name
instance-id=1234567890
";
        assert_eq!(
            parse_flatpak_info_app_id(flatpak_info).as_deref(),
            Some("org.mozilla.firefox")
        );
        assert_eq!(
            parse_flatpak_info_app_id("[Instance]\nname=org.ignored.App\n"),
            None
        );

        // Non-systemd Flatpak session falls back to `/proc/<pid>/root/.flatpak-info`.
        let proc_root = unique_temp_dir("proc-flatpak-info");
        let pid_dir = proc_root.join("401");
        fs::create_dir_all(pid_dir.join("root")).unwrap();
        fs::write(pid_dir.join("cmdline"), b"/app/lib/firefox/firefox\0").unwrap();
        fs::write(pid_dir.join("comm"), "firefox-bin\n").unwrap();
        fs::write(pid_dir.join("cgroup"), "0::/\n").unwrap();
        fs::write(pid_dir.join("root/.flatpak-info"), flatpak_info).unwrap();

        let resolved = resolve_pid_process(&pid_dir);
        assert_eq!(
            resolved.as_ref().map(|(exe, _)| exe.as_str()),
            Some("org.mozilla.firefox")
        );

        let _ = fs::remove_dir_all(&proc_root);
    }

    #[test]
    fn snap_cgroup_parsing_and_process_resolution() {
        assert_eq!(
            parse_snap_cgroup_package(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/snap.chromium.chromium-550e8400-e29b-41d4-a716-446655440000.scope\n"
            )
            .as_deref(),
            Some("chromium")
        );
        assert_eq!(
            parse_snap_cgroup_package(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/snap.obs-studio.obs-studio-12345.scope\n"
            )
            .as_deref(),
            Some("obs-studio")
        );
        assert_eq!(
            parse_snap_cgroup_package(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/snap.obs\\x2dstudio.obs\\x2dstudio-abcdef01.scope\n"
            )
            .as_deref(),
            Some("obs-studio")
        );
        assert_eq!(
            parse_snap_cgroup_package("0::/system.slice/snap.cups.cupsd.service\n"),
            None
        );
        assert_eq!(
            parse_snap_cgroup_package("0::/user.slice/user-1000.slice/session-2.scope\n"),
            None
        );

        let proc_root = unique_temp_dir("proc-snap");

        let chromium_dir = proc_root.join("501");
        fs::create_dir_all(&chromium_dir).unwrap();
        fs::write(
            chromium_dir.join("cmdline"),
            b"/snap/chromium/2810/usr/lib/chromium-browser/chrome\0",
        )
        .unwrap();
        fs::write(chromium_dir.join("comm"), "chrome\n").unwrap();
        fs::write(
            chromium_dir.join("cgroup"),
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/snap.chromium.chromium-550e8400-e29b-41d4-a716-446655440000.scope\n",
        )
        .unwrap();

        let obs_dir = proc_root.join("502");
        fs::create_dir_all(&obs_dir).unwrap();
        fs::write(obs_dir.join("cmdline"), b"/snap/obs-studio/1284/usr/bin/obs\0").unwrap();
        fs::write(obs_dir.join("comm"), "obs\n").unwrap();
        fs::write(
            obs_dir.join("cgroup"),
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/snap.obs-studio.obs-studio-998877.scope\n",
        )
        .unwrap();

        assert_eq!(
            resolve_pid_process(&chromium_dir)
                .as_ref()
                .map(|(exe, _)| exe.as_str()),
            Some("chromium")
        );
        assert_eq!(
            resolve_pid_process(&obs_dir)
                .as_ref()
                .map(|(exe, _)| exe.as_str()),
            Some("obs-studio")
        );

        let mut apps = Vec::new();
        discover_proc_apps(&proc_root, &mut apps);
        apps.sort_by(|a, b| a.exe_name.cmp(&b.exe_name));
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].exe_name, "chromium");
        assert_eq!(apps[1].exe_name, "obs-studio");

        let _ = fs::remove_dir_all(&proc_root);
    }

    #[test]
    fn desktop_application_dirs_respects_xdg_data_dirs_and_fallbacks() {
        let dirs = desktop_application_dirs_from(
            Some(OsStr::new(
                "/run/current-system/sw/share::relative/dir:/usr/share:/opt/custom/share/",
            )),
            Some(OsStr::new("/home/alice/.custom-share")),
            Some(OsStr::new("/home/alice")),
            Some(PathBuf::from("/home/bob")),
        );

        assert!(dirs.contains(&PathBuf::from("/run/current-system/sw/share/applications")));
        assert!(dirs.contains(&PathBuf::from("/opt/custom/share/applications")));
        assert!(!dirs.contains(&PathBuf::from("relative/dir/applications")));
        for std_dir in SYSTEM_DESKTOP_DIRS {
            assert!(dirs.contains(&PathBuf::from(std_dir)));
        }
        assert!(dirs.contains(&PathBuf::from("/home/alice/.custom-share/applications")));
        assert!(dirs.contains(&PathBuf::from("/home/bob/.local/share/applications")));

        // `/usr/share/applications` appears only once despite being in both XDG_DATA_DIRS and SYSTEM_DESKTOP_DIRS.
        let usr_share_count = dirs
            .iter()
            .filter(|p| *p == Path::new("/usr/share/applications"))
            .count();
        assert_eq!(usr_share_count, 1);

        // `resolve_user_home_via_getpwnam` rejects invalid/root usernames.
        assert_eq!(resolve_user_home_via_getpwnam("root"), None);
        assert_eq!(resolve_user_home_via_getpwnam(""), None);
        assert_eq!(resolve_user_home_via_getpwnam("bad:name"), None);
        assert_eq!(resolve_user_home_via_getpwnam("bad/name"), None);
    }

    #[test]
    fn flatpak_cgroup_resolution_sandbox_filtering_and_sudo_home_lookup() {
        assert_eq!(
            parse_flatpak_cgroup_app_id(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-com.discordapp.Discord-12345.scope\n"
            )
            .as_deref(),
            Some("com.discordapp.Discord")
        );
        assert_eq!(
            parse_flatpak_cgroup_app_id(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-io.gitlab.librewolf\\x2dcommunity-99.scope\n"
            )
            .as_deref(),
            Some("io.gitlab.librewolf-community")
        );
        assert_eq!(
            parse_flatpak_cgroup_app_id("0::/user.slice/user-1000.slice/session-2.scope\n"),
            None
        );

        let proc_root = unique_temp_dir("proc-flatpak");

        // Sandbox helpers must be skipped from discover_proc_apps()
        for (pid, comm) in [
            ("301", "bwrap"),
            ("302", "xdg-dbus-proxy"),
            ("303", "zypak-helper"),
        ] {
            let dir = proc_root.join(pid);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("cmdline"), format!("/usr/bin/{comm}\0")).unwrap();
            fs::write(dir.join("comm"), format!("{comm}\n")).unwrap();
            fs::write(
                dir.join("cgroup"),
                "0::/user.slice/user-1000.slice/app.slice/app-flatpak-com.discordapp.Discord-12345.scope\n",
            )
            .unwrap();
        }

        // Socket lookup on zypak-helper inside Flatpak cgroup still resolves to Flatpak app ID
        let zypak_resolved = resolve_pid_process(&proc_root.join("303"));
        assert_eq!(
            zypak_resolved.as_ref().map(|(exe, _)| exe.as_str()),
            Some("com.discordapp.Discord")
        );

        // Actual Flatpak app process is discovered with its Flatpak app ID
        let discord_dir = proc_root.join("304");
        fs::create_dir_all(&discord_dir).unwrap();
        fs::write(discord_dir.join("cmdline"), b"/app/discord/Discord\0").unwrap();
        fs::write(discord_dir.join("comm"), "Discord\n").unwrap();
        fs::write(
            discord_dir.join("cgroup"),
            "0::/user.slice/user-1000.slice/app.slice/app-flatpak-com.discordapp.Discord-12345.scope\n",
        )
        .unwrap();

        let mut apps = Vec::new();
        discover_proc_apps(&proc_root, &mut apps);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].exe_name, "com.discordapp.Discord");

        let _ = fs::remove_dir_all(&proc_root);

        // Snap dir present in SYSTEM_DESKTOP_DIRS
        assert!(SYSTEM_DESKTOP_DIRS.contains(&"/var/lib/snapd/desktop/applications"));

        // SUDO_USER /etc/passwd lookup
        let passwd = "root:x:0:0:root:/root:/bin/bash\narda:x:1000:1000:Arda:/home/arda:/bin/zsh\n";
        assert_eq!(
            resolve_user_home_from_passwd(passwd, "arda"),
            Some(PathBuf::from("/home/arda"))
        );
        assert_eq!(resolve_user_home_from_passwd(passwd, "root"), None);
        assert_eq!(resolve_user_home_from_passwd(passwd, "missing"), None);
    }

    #[test]
    fn ignored_app_names_skip_vdpi_and_vdpi_desktop() {
        assert!(is_ignored_app_name(""));
        assert!(is_ignored_app_name("vdpi"));
        assert!(is_ignored_app_name("vdpi-desktop"));
        assert!(is_ignored_app_name("  VDPI-Desktop \n"));
        assert!(is_ignored_app_name("vdpi-desktop-linux-x86_64.AppImage"));
        assert!(is_ignored_app_name("VDPI-DESKTOP-0.8.0-x86_64.AppImage"));
        assert!(!is_ignored_app_name("firefox"));
        assert!(!is_ignored_app_name("vdpi-helper"));

        let desktop_gui_entry = "\
[Desktop Entry]
Type=Application
Name=vdpi Desktop
Exec=/usr/bin/vdpi-desktop
";
        assert!(parse_desktop_entry(desktop_gui_entry).is_none());

        let appimage_gui_entry = "\
[Desktop Entry]
Type=Application
Name=vdpi Desktop AppImage
Exec=/opt/vdpi/vdpi-desktop-linux-x86_64.AppImage
";
        assert!(parse_desktop_entry(appimage_gui_entry).is_none());

        let proc_root = unique_temp_dir("proc-vdpi-desktop");
        let gui_pid = proc_root.join("101");
        fs::create_dir_all(&gui_pid).unwrap();
        fs::write(gui_pid.join("cmdline"), b"/usr/bin/vdpi-desktop\0").unwrap();
        fs::write(gui_pid.join("comm"), "vdpi-desktop\n").unwrap();

        let appimage_pid = proc_root.join("102");
        fs::create_dir_all(&appimage_pid).unwrap();
        fs::write(
            appimage_pid.join("cmdline"),
            b"/home/user/Applications/vdpi-desktop-linux-x86_64.AppImage\0",
        )
        .unwrap();
        fs::write(appimage_pid.join("comm"), "vdpi-desktop-li\n").unwrap();

        let firefox_pid = proc_root.join("202");
        fs::create_dir_all(&firefox_pid).unwrap();
        fs::write(firefox_pid.join("cmdline"), b"/usr/bin/firefox\0").unwrap();
        fs::write(firefox_pid.join("comm"), "firefox\n").unwrap();

        let mut apps = Vec::new();
        discover_proc_apps(&proc_root, &mut apps);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].exe_name, "firefox");

        let _ = fs::remove_dir_all(&proc_root);
    }
}
