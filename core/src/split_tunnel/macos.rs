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

/// Resolves the owning process command name for `(local_port, is_udp)` using
/// `/usr/sbin/lsof -nP -F c -iTCP:<port>` (or `-iUDP:<port>`).
///
/// Returns `None` if `local_port == 0`, `/usr/sbin/lsof` is unavailable, `lsof`
/// exits with a non-zero status, or no non-`vdpi` command entry is reported.
pub(super) fn lookup_local_port_process(
    local_ip: IpAddr,
    local_port: u16,
    is_udp: bool,
) -> Option<String> {
    let _ = local_ip;
    if local_port == 0 {
        return None;
    }

    let filter = if is_udp {
        format!("-iUDP:{local_port}")
    } else {
        format!("-iTCP:{local_port}")
    };

    let output = Command::new("/usr/sbin/lsof")
        .args(["-nP", "-F", "c", &filter])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_lsof_command_output(&stdout)
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
    let exe_from_plist = fs::read_to_string(&plist_path)
        .ok()
        .and_then(|xml| parse_info_plist_executable(&xml));

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

/// Extracts `<key>CFBundleExecutable</key><string>...</string>` from an XML
/// `Info.plist` document.
///
/// Returns `None` for binary plists, malformed XML, missing keys, non-string
/// values, or empty executable names.
fn parse_info_plist_executable(plist_xml: &str) -> Option<String> {
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
    if trimmed.is_empty() {
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

/// Parses the stdout of `/usr/sbin/lsof -nP -F c -iTCP:<port>` (or `-iUDP:<port>`)
/// and returns the first non-empty, non-`vdpi` `c<command>` field with `\xHH`
/// escapes decoded.
fn parse_lsof_command_output(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        let Some(raw_cmd) = line.strip_prefix('c') else {
            continue;
        };
        let decoded = unescape_lsof_command(raw_cmd);
        let cmd = decoded.trim();
        if cmd.is_empty() || is_self_binary(cmd) {
            continue;
        }
        return Some(cmd.to_string());
    }
    None
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
    fn parses_lsof_command_output_basic_and_hex_escaped() {
        let sample = "p12345\ncDiscord\nf14\n";
        assert_eq!(
            parse_lsof_command_output(sample).as_deref(),
            Some("Discord")
        );

        let escaped = "p22222\ncGoogle\\x20Chrome\n";
        assert_eq!(
            parse_lsof_command_output(escaped).as_deref(),
            Some("Google Chrome")
        );
    }

    #[test]
    fn lsof_parser_skips_vdpi_self_and_handles_empty_or_malformed() {
        let with_self = "p100\ncvdpi\np200\ncRobloxPlayer\n";
        assert_eq!(
            parse_lsof_command_output(with_self).as_deref(),
            Some("RobloxPlayer")
        );

        assert_eq!(parse_lsof_command_output("p100\ncvdpi\n"), None);
        assert_eq!(parse_lsof_command_output(""), None);
        assert_eq!(parse_lsof_command_output("p100\nf4\n"), None);
        assert_eq!(
            parse_lsof_command_output("p99\ncApp\\xZZName\n").as_deref(),
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
