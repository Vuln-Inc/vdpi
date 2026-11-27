//! macOS split-tunnel application discovery (`.app` bundles + running `ps`
//! processes) and local socket-to-process resolution via `/usr/sbin/lsof`.

use std::collections::HashSet;
use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{AppCategory, DiscoveredApp};

/// Maximum directory recursion depth when scanning macOS Applications folders
/// (depth 2 finds both `/Applications/Foo.app` and `/Applications/Utilities/Bar.app`).
const APP_SCAN_MAX_DEPTH: usize = 2;

/// Magic header prefix for Apple binary property list (`Info.plist`) files.
const BINARY_PLIST_MAGIC: &[u8] = b"bplist00";

/// Path prefixes belonging to macOS system daemons and frameworks rather than
/// user-facing applications. (`/System/Applications/` is deliberately excluded
/// so built-in apps like Safari and Mail remain discoverable.)
const IGNORED_PROCESS_PATH_PREFIXES: &[&str] = &[
    "/system/library/",
    "/usr/libexec/",
    "/usr/sbin/",
    "/sbin/",
    "/library/apple/",
    "/private/var/db/",
];

/// Path segments belonging to internal XPC services, app extensions, and
/// embedded framework helpers.
const IGNORED_PROCESS_PATH_SEGMENTS: &[&str] = &[".xpc/", ".appex/", "/contents/frameworks/"];

/// Lowercased process basenames filtered out of running application discovery
/// (OS daemons, login shells, lookup utilities, and `vdpi` itself).
const IGNORED_PROCESS_NAMES: &[&str] = &[
    "vdpi",
    "vdpi-cli",
    "launchd",
    "kernel_task",
    "syslogd",
    "logd",
    "windowserver",
    "loginwindow",
    "cfprefsd",
    "distnoted",
    "notifyd",
    "trustd",
    "mdnsresponder",
    "configd",
    "fseventsd",
    "mds",
    "mds_stores",
    "mds_sync",
    "coreaudiod",
    "bluetoothd",
    "airportd",
    "powerd",
    "usereventagent",
    "dock",
    "finder",
    "systemuiserver",
    "controlcenter",
    "notificationcenter",
    "spotlight",
    "runningboardd",
    "containermanagerd",
    "symptomsd",
    "nsurlsessiond",
    "cloudd",
    "bird",
    "accountsd",
    "secd",
    "securityd",
    "lsd",
    "tccd",
    "opendirectoryd",
    "diskarbitrationd",
    "coreduetd",
    "dasd",
    "locationd",
    "biometrickitd",
    "mediaremoted",
    "rapportd",
    "sharingd",
    "assistantd",
    "chronod",
    "homed",
    "identityservicesd",
    "imagent",
    "apsd",
    "commcenter",
    "watchdogd",
    "usbd",
    "hidd",
    "thermald",
    "timed",
    "cron",
    "crond",
    "sshd",
    "sudo",
    "su",
    "login",
    "ps",
    "lsof",
    "sh",
    "bash",
    "zsh",
    "fish",
    "csh",
    "tcsh",
    "dash",
    "ksh",
    "crashpad_handler",
];

/// Discovers installed `.app` bundles across `/Applications`, `~/Applications`,
/// and `/System/Applications` (depth 2) as well as currently running user
/// processes via `/bin/ps -axo comm=`.
pub(super) fn discover_platform_apps() -> Vec<DiscoveredApp> {
    let mut apps = Vec::new();

    for dir in default_application_dirs() {
        scan_app_bundles_in_dir(&dir, APP_SCAN_MAX_DEPTH, &mut apps);
    }

    apps.extend(discover_running_apps());
    apps
}

/// Resolves the owning process command name for `(local_ip, local_port, is_udp)`
/// using `/usr/sbin/lsof -nP +c 0 -F cn -iTCP:<port>` (or `-iUDP:<port>`),
/// verifying that the local endpoint (never the remote endpoint) matches
/// `local_port` and normalizing browser/Electron helper process names back to
/// their parent app.
///
/// Returns `None` if `local_port == 0`, `/usr/sbin/lsof` is unavailable, `lsof`
/// exits with a non-zero status, or no non-`vdpi` matching local socket is reported.
pub(super) fn lookup_local_port_process(
    local_ip: IpAddr,
    local_port: u16,
    is_udp: bool,
) -> Option<String> {
    if local_port == 0 {
        return None;
    }

    let filter = if is_udp {
        format!("-iUDP:{local_port}")
    } else {
        format!("-iTCP:{local_port}")
    };

    let output = Command::new("/usr/sbin/lsof")
        .args(["-nP", "+c", "0", "-F", "cn", &filter])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_lsof_output(&stdout, local_ip, local_port)
}

fn default_application_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from("/Applications")];
    if let Some(home) = env::var_os("HOME").filter(|h| !h.is_empty()) {
        dirs.push(PathBuf::from(home).join("Applications"));
    }
    dirs.push(PathBuf::from("/System/Applications"));
    dirs
}

fn is_self_binary(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    lower == "vdpi" || lower == "vdpi-cli"
}

fn is_app_bundle_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
}

#[cfg(unix)]
fn is_executable_file(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.is_file() && (meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable_file(meta: &fs::Metadata) -> bool {
    meta.is_file()
}

fn scan_app_bundles_in_dir(dir: &Path, remaining_depth: usize, out: &mut Vec<DiscoveredApp>) {
    if remaining_depth == 0 {
        return;
    }

    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if is_app_bundle_extension(&path) {
            if path.is_dir() {
                out.extend(inspect_app_bundle(&path));
            }
            continue;
        }

        if remaining_depth > 1 && entry.file_type().is_ok_and(|ft| ft.is_dir()) {
            scan_app_bundles_in_dir(&path, remaining_depth - 1, out);
        }
    }
}

fn inspect_app_bundle(bundle_path: &Path) -> Option<DiscoveredApp> {
    if !is_app_bundle_extension(bundle_path) {
        return None;
    }

    let display_name = bundle_path.file_stem()?.to_str()?.trim();
    if display_name.is_empty() {
        return None;
    }

    let contents_dir = bundle_path.join("Contents");
    let plist_path = contents_dir.join("Info.plist");
    let exe_from_plist = read_info_plist_executable(&plist_path);

    let exe_name = exe_from_plist
        .or_else(|| find_first_executable_in_macos_dir(&contents_dir.join("MacOS")))
        .unwrap_or_else(|| display_name.to_string());

    if exe_name.trim().is_empty() || is_self_binary(&exe_name) {
        return None;
    }

    Some(DiscoveredApp {
        display_name: display_name.to_string(),
        exe_name,
        path: Some(bundle_path.to_string_lossy().into_owned()),
        is_running: false,
        category: AppCategory::Installed,
    })
}

fn find_first_executable_in_macos_dir(macos_dir: &Path) -> Option<String> {
    let entries = fs::read_dir(macos_dir).ok()?;
    let mut candidates = Vec::new();

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.starts_with('.') {
            continue;
        }
        if fs::metadata(entry.path())
            .ok()
            .is_some_and(|meta| is_executable_file(&meta))
        {
            candidates.push(trimmed.to_string());
        }
    }

    candidates.sort_by(|a, b| {
        a.to_ascii_lowercase()
            .cmp(&b.to_ascii_lowercase())
            .then_with(|| a.cmp(b))
    });
    candidates.into_iter().next()
}

fn is_binary_plist(bytes: &[u8]) -> bool {
    bytes.starts_with(BINARY_PLIST_MAGIC)
}

/// Reads `CFBundleExecutable` from a bundle's `Info.plist`.
///
/// For binary plists starting with `b"bplist00"`, invokes `/usr/bin/plutil`
/// (`-extract CFBundleExecutable raw -o - <plist_path>`); for XML plists,
/// parses `<key>CFBundleExecutable</key><string>...</string>` directly.
fn read_info_plist_executable(plist_path: &Path) -> Option<String> {
    let bytes = fs::read(plist_path).ok()?;
    if is_binary_plist(&bytes) {
        return extract_binary_plist_executable(plist_path);
    }

    let xml = String::from_utf8(bytes).ok()?;
    parse_info_plist_executable(&xml)
}

fn extract_binary_plist_executable(plist_path: &Path) -> Option<String> {
    let output = Command::new("/usr/bin/plutil")
        .args(["-extract", "CFBundleExecutable", "raw", "-o", "-"])
        .arg(plist_path)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    sanitize_executable_name(&stdout)
}

/// Extracts `<key>CFBundleExecutable</key><string>...</string>` from an XML
/// `Info.plist` document.
///
/// Returns `None` for binary plists, malformed XML, missing keys, non-string
/// values, or empty executable names.
fn parse_info_plist_executable(plist_xml: &str) -> Option<String> {
    if is_binary_plist(plist_xml.as_bytes()) {
        return None;
    }

    let mut cursor = plist_xml;

    while let Some(key_start) = cursor.find("<key>") {
        let after_open = &cursor[key_start + "<key>".len()..];
        let key_end = after_open.find("</key>")?;
        let key_name = after_open[..key_end].trim();
        let after_key = &after_open[key_end + "</key>".len()..];

        if key_name == "CFBundleExecutable" {
            let value_area = skip_xml_trivia(after_key);
            let after_string_open = value_area.strip_prefix("<string>")?;
            let string_end = after_string_open.find("</string>")?;
            let raw_val = &after_string_open[..string_end];
            let decoded = unescape_xml_entities(raw_val);
            return sanitize_executable_name(&decoded);
        }

        cursor = after_key;
    }

    None
}

fn skip_xml_trivia(mut input: &str) -> &str {
    loop {
        let trimmed = input.trim_start();
        match trimmed
            .strip_prefix("<!--")
            .and_then(|rest| rest.find("-->").map(|end| &rest[end + "-->".len()..]))
        {
            Some(after_comment) => input = after_comment,
            None => return trimmed,
        }
    }
}

fn unescape_xml_entities(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_string();
    }

    raw.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn sanitize_executable_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains(['\n', '\r', '\0']) {
        return None;
    }
    let base = trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed).trim();
    if base.is_empty() || base == "." || base == ".." {
        return None;
    }
    Some(base.to_string())
}

fn discover_running_apps() -> Vec<DiscoveredApp> {
    let Ok(output) = Command::new("/bin/ps").args(["-axo", "comm="]).output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_ps_comm_output(&stdout)
}

fn parse_ps_comm_output(stdout: &str) -> Vec<DiscoveredApp> {
    let mut apps = Vec::new();
    let mut seen = HashSet::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if is_ignored_process_path(trimmed) {
            continue;
        }

        let raw_basename = trimmed.rsplit('/').next().unwrap_or(trimmed).trim();
        let basename = raw_basename.trim_start_matches('-').trim();
        if basename.is_empty() || is_ignored_process_name(basename) {
            continue;
        }

        let dedup_key = basename.to_ascii_lowercase();
        if !seen.insert(dedup_key) {
            continue;
        }

        let display_name =
            extract_app_bundle_stem_from_path(trimmed).unwrap_or_else(|| basename.to_string());
        let path = if trimmed.starts_with('/') {
            Some(trimmed.to_string())
        } else {
            None
        };

        apps.push(DiscoveredApp {
            display_name,
            exe_name: basename.to_string(),
            path,
            is_running: true,
            category: AppCategory::Running,
        });
    }

    apps
}

fn is_ignored_process_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    IGNORED_PROCESS_PATH_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
        || IGNORED_PROCESS_PATH_SEGMENTS
            .iter()
            .any(|segment| lower.contains(segment))
}

fn is_ignored_process_name(basename: &str) -> bool {
    let lower = basename.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return true;
    }
    if IGNORED_PROCESS_NAMES.contains(&lower.as_str()) {
        return true;
    }
    lower.ends_with(" helper") || lower.contains(" helper (")
}

fn extract_app_bundle_stem_from_path(path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    let marker = ".app/contents/macos/";
    let marker_idx = lower.find(marker)?;
    let bundle_prefix = &path[..marker_idx];
    let stem = bundle_prefix
        .rsplit('/')
        .next()
        .unwrap_or(bundle_prefix)
        .trim();
    if stem.is_empty() {
        None
    } else {
        Some(stem.to_string())
    }
}

/// Maps macOS browser and Electron helper process names (including 15-character
/// kernel `p_comm` truncated `lsof` command names) back to their parent
/// application name so split-tunnel rules targeting the user-facing app match
/// network-owning helpers.
fn normalize_macos_helper_process(cmd: &str) -> String {
    let raw_lower = cmd.to_ascii_lowercase();
    let trimmed = cmd.trim();
    let lower = trimmed.to_ascii_lowercase();

    if lower == "com.apple.webkit.networking"
        || lower.starts_with("com.apple.webkit.")
        || lower == "com.apple.webki"
        || lower == "safari web content"
        || lower.starts_with("safari web cont")
        || lower == "safaribookmarkssyncagent"
    {
        return "Safari".to_string();
    }

    if lower == "google chrome h" || lower.starts_with("google chrome helper") {
        return "Google Chrome".to_string();
    }

    if lower == "brave browser h" || lower.starts_with("brave browser helper") {
        return "Brave Browser".to_string();
    }

    // "Microsoft Edge Helper" truncates to 15-char kernel p_comm "Microsoft Edge "
    // (which trims to "Microsoft Edge"); also match 16-char and full helper names.
    if raw_lower == "microsoft edge "
        || lower == "microsoft edge"
        || lower == "microsoft edge h"
        || lower.starts_with("microsoft edge helper")
    {
        return "Microsoft Edge".to_string();
    }

    if lower == "firefoxcp"
        || lower.starts_with("firefoxcp ")
        || lower == "plugin-container"
        || lower == "plugin-containe"
    {
        return "Firefox".to_string();
    }

    if lower == "discord ptb hel" || lower.starts_with("discord ptb helper") {
        return "Discord PTB".to_string();
    }

    // "Discord Canary Helper" truncates to 15-char kernel p_comm "Discord Canary "
    // (which trims to "Discord Canary"); also match 16-char and full helper names.
    if raw_lower == "discord canary "
        || lower == "discord canary"
        || lower == "discord canary h"
        || lower.starts_with("discord canary helper")
    {
        return "Discord Canary".to_string();
    }

    // Generic Electron / Chromium helper suffix (e.g. "Discord Helper",
    // "Discord Helper (Renderer)", "Slack Helper (GPU)", "Spotify Helper").
    if let Some(idx) = lower.find(" helper") {
        let after = &lower[idx + " helper".len()..];
        if after.is_empty() || after.starts_with(" (") || after.starts_with(' ') {
            let parent = trimmed[..idx].trim();
            if !parent.is_empty() {
                return parent.to_string();
            }
        }
    }

    trimmed.to_string()
}

/// Extracts `(optional_local_ip, local_port)` from an `lsof -F n` network name
/// field (`local->remote` or `local`), strictly ignoring any remote endpoint.
///
/// Returns `Ok` (`Some((None, port))`) for wildcard binds (`*:port`) and
/// `Some((Some(ip), port))` for concrete IPv4/IPv6 binds.
fn parse_lsof_local_endpoint(name_field: &str) -> Option<(Option<IpAddr>, u16)> {
    let local_with_state = name_field.split("->").next().unwrap_or(name_field).trim();
    let local_part = local_with_state.split_whitespace().next()?;
    let (host_raw, port_raw) = local_part.rsplit_once(':')?;
    let port = port_raw.parse::<u16>().ok()?;
    let host = host_raw.trim();

    if host == "*" {
        return Some((None, port));
    }

    let unwrapped = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    let without_zone = unwrapped.split('%').next().unwrap_or(unwrapped);
    let ip: IpAddr = without_zone.parse().ok()?;
    Some((Some(ip.to_canonical()), port))
}

/// Parses the stdout of `/usr/sbin/lsof -nP +c 0 -F cn -iTCP:<port>` (or `-iUDP:<port>`)
/// and returns the normalized owning application name for the first entry whose
/// **local** endpoint matches `(local_ip, local_port)`, preferring an exact IP
/// match over a wildcard (`*` / `0.0.0.0` / `::`) bind and ignoring sockets that
/// only match `local_port` on their remote endpoint.
fn parse_lsof_output(stdout: &str, local_ip: IpAddr, local_port: u16) -> Option<String> {
    let target_ip = local_ip.to_canonical();
    let mut current_cmd: Option<String> = None;
    let mut wildcard_match: Option<String> = None;

    for line in stdout.lines() {
        if line.starts_with('p') {
            current_cmd = None;
            continue;
        }
        if let Some(raw_cmd) = line.strip_prefix('c') {
            let decoded = unescape_lsof_command(raw_cmd);
            let cmd = decoded.trim();
            if cmd.is_empty() || is_self_binary(cmd) {
                current_cmd = None;
            } else {
                current_cmd = Some(normalize_macos_helper_process(cmd));
            }
            continue;
        }
        if let Some(raw_name) = line.strip_prefix('n') {
            let Some(ref cmd) = current_cmd else {
                continue;
            };
            let Some((ep_ip, ep_port)) = parse_lsof_local_endpoint(raw_name) else {
                continue;
            };
            if ep_port != local_port {
                continue;
            }
            if target_ip.is_unspecified() {
                return Some(cmd.clone());
            }
            match ep_ip {
                Some(ip) if ip == target_ip => return Some(cmd.clone()),
                None if wildcard_match.is_none() => {
                    wildcard_match = Some(cmd.clone());
                }
                Some(IpAddr::V4(v4))
                    if v4.is_unspecified() && target_ip.is_ipv4() && wildcard_match.is_none() =>
                {
                    wildcard_match = Some(cmd.clone());
                }
                Some(IpAddr::V6(v6)) if v6.is_unspecified() && wildcard_match.is_none() => {
                    wildcard_match = Some(cmd.clone());
                }
                _ => {}
            }
        }
    }

    wildcard_match
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_hex_escape(bytes: &[u8]) -> Option<u8> {
    if bytes.len() >= 4 && bytes[0] == b'\\' && bytes[1] == b'x' {
        let hi = hex_nibble(bytes[2])?;
        let lo = hex_nibble(bytes[3])?;
        Some((hi << 4) | lo)
    } else {
        None
    }
}

fn unescape_lsof_command(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if let Some(decoded) = parse_hex_escape(&bytes[i..]) {
            out.push(decoded);
            i += 4;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = env::temp_dir().join(format!(
            "vdpi-macos-split-tunnel-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create temp test dir");
        dir
    }

    #[test]
    fn parses_info_plist_cf_bundle_executable() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Google Chrome</string>
    <key>CFBundleExecutable</key>
    <string>Google Chrome</string>
</dict>
</plist>"#;

        assert_eq!(
            parse_info_plist_executable(xml).as_deref(),
            Some("Google Chrome")
        );
    }

    #[test]
    fn parses_info_plist_inline_with_comments_and_entities() {
        let xml = "<dict><key>CFBundleExecutable</key><!-- main --><string>Rock &amp; Roll</string></dict>";
        assert_eq!(
            parse_info_plist_executable(xml).as_deref(),
            Some("Rock & Roll")
        );
    }

    #[test]
    fn rejects_missing_non_string_or_binary_info_plist() {
        assert_eq!(parse_info_plist_executable("bplist00\x00\x01binary"), None);
        assert_eq!(
            parse_info_plist_executable(
                "<dict><key>CFBundleExecutable</key><true/><key>CFBundleName</key><string>Wrong</string></dict>"
            ),
            None
        );
        assert_eq!(
            parse_info_plist_executable(
                "<dict><key>CFBundleExecutable</key><string>   </string></dict>"
            ),
            None
        );
        assert_eq!(
            parse_info_plist_executable(
                "<dict><key>CFBundleExecutableExtra</key><string>No</string></dict>"
            ),
            None
        );
    }

    #[test]
    fn parses_lsof_output_local_only_hex_escaped_and_maps_helpers() {
        let lan_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42));
        let sample = "p12345\ncDiscord\nf14\nn192.168.1.42:54321->162.159.135.232:443\n";
        assert_eq!(
            parse_lsof_output(sample, lan_ip, 54321).as_deref(),
            Some("Discord")
        );

        let escaped = "p22222\ncGoogle\\x20Chrome\nf15\nn192.168.1.42:54321->142.250.185.78:443\n";
        assert_eq!(
            parse_lsof_output(escaped, lan_ip, 54321).as_deref(),
            Some("Google Chrome")
        );

        // Remote port matching local_port must NOT match; only the local endpoint port matches.
        let remote_only = "\
p111
cWrongRemoteApp
f10
n192.168.1.42:60000->1.1.1.1:54321
p222
cGoogle\\x20Chrome\\x20H
f11
n192.168.1.42:54321->142.250.185.78:443
";
        assert_eq!(
            parse_lsof_output(remote_only, lan_ip, 54321).as_deref(),
            Some("Google Chrome")
        );
        assert_eq!(
            parse_lsof_output(
                "p111\ncWrongRemoteApp\nf10\nn192.168.1.42:60000->1.1.1.1:54321\n",
                lan_ip,
                54321
            ),
            None
        );

        // Wildcard bind fallback (`*:port`) matches when exact IP is not present.
        let wildcard = "p333\ncDiscord\\x20Helper\nf12\nn*:54321\n";
        assert_eq!(
            parse_lsof_output(wildcard, lan_ip, 54321).as_deref(),
            Some("Discord")
        );
    }

    #[test]
    fn maps_macos_browser_and_electron_helpers_to_parent_apps() {
        for (helper, expected) in [
            ("Discord Helper", "Discord"),
            ("Discord Helper (Renderer)", "Discord"),
            ("Discord Helper (GPU)", "Discord"),
            ("Google Chrome H", "Google Chrome"),
            ("Google Chrome Helper (Renderer)", "Google Chrome"),
            ("Brave Browser H", "Brave Browser"),
            ("Brave Browser Helper", "Brave Browser"),
            ("Brave Browser Helper (Renderer)", "Brave Browser"),
            ("Microsoft Edge ", "Microsoft Edge"),
            ("microsoft edge ", "Microsoft Edge"),
            ("Microsoft Edge H", "Microsoft Edge"),
            ("Microsoft Edge Helper", "Microsoft Edge"),
            ("Microsoft Edge Helper (Renderer)", "Microsoft Edge"),
            ("Discord PTB Hel", "Discord PTB"),
            ("Discord PTB Helper", "Discord PTB"),
            ("Discord PTB Helper (Renderer)", "Discord PTB"),
            ("Discord Canary ", "Discord Canary"),
            ("discord canary ", "Discord Canary"),
            ("Discord Canary H", "Discord Canary"),
            ("Discord Canary Helper", "Discord Canary"),
            ("Discord Canary Helper (GPU)", "Discord Canary"),
            ("Safari Web Content", "Safari"),
            ("Safari Web Cont", "Safari"),
            ("com.apple.WebKit.Networking", "Safari"),
            ("com.apple.WebKi", "Safari"),
            ("FirefoxCP", "Firefox"),
            ("FirefoxCP Web Content", "Firefox"),
            ("plugin-container", "Firefox"),
            ("plugin-containe", "Firefox"),
            ("Slack Helper (Network)", "Slack"),
            ("Spotify Helper", "Spotify"),
            ("RobloxPlayer", "RobloxPlayer"),
        ] {
            assert_eq!(
                normalize_macos_helper_process(helper),
                expected,
                "expected helper '{helper}' to map to '{expected}'"
            );
        }
    }

    #[test]
    fn normalizes_full_and_15_char_p_comm_truncated_helpers_and_lsof_output() {
        let truncated_15_cases = [
            ("Google Chrome Helper (Renderer)", "Google Chrome H", "Google Chrome"),
            ("Brave Browser Helper (Renderer)", "Brave Browser H", "Brave Browser"),
            ("Microsoft Edge Helper (Renderer)", "Microsoft Edge ", "Microsoft Edge"),
            ("Discord PTB Helper (Renderer)", "Discord PTB Hel", "Discord PTB"),
            ("Discord Canary Helper (Renderer)", "Discord Canary ", "Discord Canary"),
            ("Safari Web Content", "Safari Web Cont", "Safari"),
            ("com.apple.WebKit.Networking", "com.apple.WebKi", "Safari"),
            ("FirefoxCP Web Content", "FirefoxCP Web C", "Firefox"),
            ("plugin-container", "plugin-containe", "Firefox"),
            ("Discord Helper (Renderer)", "Discord Helper ", "Discord"),
            ("Slack Helper (Network)", "Slack Helper (N", "Slack"),
        ];

        for (full, truncated_15, expected) in truncated_15_cases {
            assert_eq!(
                truncated_15.len(),
                15,
                "kernel p_comm test input '{truncated_15}' must be 15 bytes"
            );
            assert_eq!(
                &full[..15], truncated_15,
                "'{truncated_15}' must be the 15-byte prefix of '{full}'"
            );
            assert_eq!(
                normalize_macos_helper_process(full),
                expected,
                "full helper '{full}' should normalize to '{expected}'"
            );
            assert_eq!(
                normalize_macos_helper_process(truncated_15),
                expected,
                "15-char truncated helper '{truncated_15}' should normalize to '{expected}'"
            );
        }

        // Verify lowercase 15-char trailing-space prefixes normalize to canonical app names.
        assert_eq!(normalize_macos_helper_process("microsoft edge "), "Microsoft Edge");
        assert_eq!(normalize_macos_helper_process("discord canary "), "Discord Canary");

        // Verify lsof +c 0 hex-escaped outputs for both 15-char p_comm and full helper names.
        let lan_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42));
        for (lsof_cmd, expected) in [
            ("Microsoft\\x20Edge\\x20", "Microsoft Edge"),
            ("Microsoft\\x20Edge\\x20Helper\\x20(Renderer)", "Microsoft Edge"),
            ("Discord\\x20Canary\\x20", "Discord Canary"),
            ("Discord\\x20Canary\\x20Helper\\x20(GPU)", "Discord Canary"),
            ("Discord\\x20PTB\\x20Hel", "Discord PTB"),
            ("Brave\\x20Browser\\x20H", "Brave Browser"),
        ] {
            let sample = format!(
                "p500\nc{lsof_cmd}\nf10\nn192.168.1.42:54321->1.1.1.1:443\n"
            );
            assert_eq!(
                parse_lsof_output(&sample, lan_ip, 54321).as_deref(),
                Some(expected),
                "expected lsof command '{lsof_cmd}' to resolve to '{expected}'"
            );
        }
    }

    #[test]
    fn binary_plist_detected_and_falls_back_to_macos_dir_when_plutil_unavailable_or_invalid() {
        assert!(is_binary_plist(b"bplist00\x00\x01payload"));
        assert!(!is_binary_plist(b"<?xml version=\"1.0\"?>"));
        assert_eq!(
            parse_info_plist_executable(
                "bplist00<key>CFBundleExecutable</key><string>Ignored</string>"
            ),
            None
        );

        let root = make_temp_dir("bplist-fallback");
        let app_contents = root.join("BinaryPlistApp.app").join("Contents");
        let macos_dir = app_contents.join("MacOS");
        fs::create_dir_all(&macos_dir).expect("create mock bplist bundle");
        fs::write(app_contents.join("Info.plist"), b"bplist00\x00\x01corrupt")
            .expect("write corrupt binary plist");

        let bin_path = macos_dir.join("RealBinary");
        fs::write(&bin_path, b"#!/bin/sh\n").expect("write mock executable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bin_path, fs::Permissions::from_mode(0o755))
                .expect("chmod mock executable");
        }

        let app = inspect_app_bundle(&root.join("BinaryPlistApp.app"))
            .expect("inspect bundle with binary plist fallback");
        let _ = fs::remove_dir_all(&root);

        assert_eq!(app.display_name, "BinaryPlistApp");
        assert_eq!(app.exe_name, "RealBinary");
    }

    #[test]
    fn lsof_parser_skips_vdpi_self_and_handles_empty_or_malformed() {
        let lan_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42));
        let with_self = "\
p100
cvdpi
f10
n192.168.1.42:54321->1.1.1.1:443
p200
cRobloxPlayer
f11
n192.168.1.42:54321->128.116.1.1:443
";
        assert_eq!(
            parse_lsof_output(with_self, lan_ip, 54321).as_deref(),
            Some("RobloxPlayer")
        );

        assert_eq!(
            parse_lsof_output("p100\ncvdpi\nf10\nn192.168.1.42:54321->1.1.1.1:443\n", lan_ip, 54321),
            None
        );
        assert_eq!(parse_lsof_output("", lan_ip, 54321), None);
        assert_eq!(parse_lsof_output("p100\nf4\n", lan_ip, 54321), None);
        assert_eq!(
            parse_lsof_output(
                "p99\ncApp\\xZZName\nf8\nn192.168.1.42:54321->1.1.1.1:443\n",
                lan_ip,
                54321
            )
            .as_deref(),
            Some("App\\xZZName")
        );
    }

    #[test]
    fn parses_ps_comm_output_filters_daemons_helpers_and_vdpi() {
        let ps_out = "\
/sbin/launchd
/usr/libexec/logd
/System/Library/CoreServices/WindowServer
/System/Library/Frameworks/CoreServices.framework/Support/mds
/Applications/Discord.app/Contents/MacOS/Discord
/Applications/Discord.app/Contents/MacOS/Discord
/Applications/Discord.app/Contents/Frameworks/Discord Helper (GPU).app/Contents/MacOS/Discord Helper (GPU)
/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
/Users/arda/Applications/Roblox.app/Contents/MacOS/RobloxPlayer
/System/Applications/Safari.app/Contents/MacOS/Safari
/opt/homebrew/bin/vdpi
-zsh
curl
";

        let apps = parse_ps_comm_output(ps_out);
        let names: Vec<(&str, &str)> = apps
            .iter()
            .map(|a| (a.display_name.as_str(), a.exe_name.as_str()))
            .collect();

        assert_eq!(
            names,
            vec![
                ("Discord", "Discord"),
                ("Google Chrome", "Google Chrome"),
                ("Roblox", "RobloxPlayer"),
                ("Safari", "Safari"),
                ("curl", "curl"),
            ]
        );
        assert!(apps
            .iter()
            .all(|a| a.is_running && a.category == AppCategory::Running));
        assert_eq!(
            apps[0].path.as_deref(),
            Some("/Applications/Discord.app/Contents/MacOS/Discord")
        );
        assert_eq!(apps[4].path, None);
    }

    #[test]
    fn scans_app_bundles_to_depth_2_with_plist_and_fallbacks() {
        let root = make_temp_dir("bundles");

        // Depth 1: bundle with Info.plist CFBundleExecutable
        let roblox_contents = root.join("Roblox.app").join("Contents");
        fs::create_dir_all(roblox_contents.join("MacOS")).expect("create roblox bundle");
        fs::write(
            roblox_contents.join("Info.plist"),
            "<plist><dict><key>CFBundleExecutable</key><string>RobloxPlayer</string></dict></plist>",
        )
        .expect("write roblox plist");

        // Depth 2: nested under Utilities/, no Info.plist -> falls back to Contents/MacOS binary
        let util_macos = root
            .join("Utilities")
            .join("My Tool.app")
            .join("Contents")
            .join("MacOS");
        fs::create_dir_all(&util_macos).expect("create nested bundle");
        let bin_path = util_macos.join("mytool-bin");
        fs::write(&bin_path, b"#!/bin/sh\n").expect("write mock binary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bin_path, fs::Permissions::from_mode(0o755))
                .expect("chmod mock binary");
        }

        // Depth 1: bundle with neither Info.plist nor Contents/MacOS -> falls back to bundle stem
        fs::create_dir_all(root.join("MinimalApp.app")).expect("create minimal bundle");

        // Depth 3: too deep (should NOT be scanned at depth 2)
        fs::create_dir_all(root.join("Sub1").join("Sub2").join("TooDeep.app"))
            .expect("create depth-3 bundle");

        let mut discovered = Vec::new();
        scan_app_bundles_in_dir(&root, APP_SCAN_MAX_DEPTH, &mut discovered);

        let _ = fs::remove_dir_all(&root);

        let mut pairs: Vec<(String, String)> = discovered
            .into_iter()
            .map(|a| (a.display_name, a.exe_name))
            .collect();
        pairs.sort();

        assert_eq!(
            pairs,
            vec![
                ("MinimalApp".to_string(), "MinimalApp".to_string()),
                ("My Tool".to_string(), "mytool-bin".to_string()),
                ("Roblox".to_string(), "RobloxPlayer".to_string()),
            ]
        );
    }

    #[test]
    fn lookup_port_zero_returns_none_without_panicking() {
        assert_eq!(
            lookup_local_port_process(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, false),
            None
        );
        assert_eq!(
            lookup_local_port_process(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, true),
            None
        );
    }
}
