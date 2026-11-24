use crate::config::{DesyncMode, RuntimeConfig};
use crate::desync::EngineContext;
use crate::platform::{clear_all_system_proxies, platform_name, print_platform_proxy_status};
use crate::update::{compare_versions, parse_semver, VersionRelation};
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use anyhow::Context;
use anyhow::{bail, Result};
use reqwest::{Client, Proxy};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const LAUNCH_AGENT_LABEL: &str = "com.vdpi";
pub const SYSTEMD_UNIT_NAME: &str = "vdpi.service";
pub const WINDOWS_SERVICE_NAME: &str = "vdpi";
pub const WINDOWS_LEGACY_RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

/// Persisted active listener metadata written when `vdpi` starts so `vdpi status`
/// and `vdpi doctor` always discover rotated ports automatically.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeState {
    pub pid: u32,
    pub addr: IpAddr,
    pub port: u16,
    pub socks_port: Option<u16>,
}

fn runtime_state_write_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if crate::platform::windows::is_running_as_service() {
            let base = std::env::var_os("ProgramData")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
            return Some(base.join("vdpi").join("state.json"));
        }
        if let Some(local_appdata) = std::env::var_os("LOCALAPPDATA") {
            return Some(PathBuf::from(local_appdata).join("vdpi").join("state.json"));
        }
    }
    vdpi_root_dir().ok().map(|r| r.join("state.json"))
}

fn runtime_state_read_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    #[cfg(target_os = "windows")]
    {
        let pd = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        paths.push(pd.join("vdpi").join("state.json"));
        if let Some(local_appdata) = std::env::var_os("LOCALAPPDATA") {
            paths.push(PathBuf::from(local_appdata).join("vdpi").join("state.json"));
        }
    }
    if let Ok(root) = vdpi_root_dir() {
        let p = root.join("state.json");
        if !paths.contains(&p) {
            paths.push(p);
        }
    }
    paths
}

pub fn write_runtime_state(primary_addr: SocketAddr, socks_addr: Option<SocketAddr>) {
    let Some(path) = runtime_state_write_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        if fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    let state = RuntimeState {
        pid: std::process::id(),
        addr: primary_addr.ip(),
        port: primary_addr.port(),
        socks_port: socks_addr.map(|a| a.port()),
    };
    let Ok(json) = serde_json::to_string(&state) else {
        return;
    };
    let tmp = path.with_extension("json.tmp");
    if fs::write(&tmp, json).is_ok() {
        let _ = fs::remove_file(&path);
        let _ = fs::rename(&tmp, &path);
    }
}

pub fn clear_runtime_state(expected_pid: u32) {
    let Some(path) = runtime_state_write_path() else {
        return;
    };
    if let Ok(raw) = fs::read_to_string(&path) {
        if let Ok(state) = serde_json::from_str::<RuntimeState>(&raw) {
            if state.pid == expected_pid {
                let _ = fs::remove_file(&path);
            }
        }
    }
}

pub fn read_runtime_states() -> Vec<RuntimeState> {
    let mut states = Vec::new();
    for path in runtime_state_read_paths() {
        if let Ok(raw) = fs::read_to_string(&path) {
            if let Ok(state) = serde_json::from_str::<RuntimeState>(&raw) {
                if !states.contains(&state) {
                    states.push(state);
                }
            }
        }
    }
    states
}

pub fn home_dir() -> Result<PathBuf> {
    if let Some(h) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(h));
    }
    if let Some(up) = std::env::var_os("USERPROFILE") {
        return Ok(PathBuf::from(up));
    }
    bail!("neither HOME nor USERPROFILE environment variable is set")
}

pub fn vdpi_root_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if let Some(program_files) = std::env::var_os("ProgramFiles") {
            return Ok(PathBuf::from(program_files).join("vdpi"));
        }
        Ok(PathBuf::from(r"C:\Program Files").join("vdpi"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(home_dir()?.join(".vdpi"))
    }
}

pub fn installed_binary_path() -> Result<PathBuf> {
    let bin_name = if cfg!(windows) { "vdpi.exe" } else { "vdpi" };
    Ok(vdpi_root_dir()?.join("bin").join(bin_name))
}

/// Snapshot of an existing `vdpi` installation discovered on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledInfo {
    pub binary_path: PathBuf,
    pub installed_version: Option<String>,
    pub current_version: &'static str,
    pub relation: VersionRelation,
    pub running_from_installed: bool,
}

/// Detects whether `vdpi` is installed in its standard service location and
/// probes the installed binary's version offline without network requests.
pub fn detect_installed_info() -> Option<InstalledInfo> {
    let binary_path = installed_binary_path().ok()?;
    if !binary_path.is_file() {
        return None;
    }

    let running_from_installed = std::env::current_exe().ok().is_some_and(|current_exe| {
        match (
            fs::canonicalize(&current_exe),
            fs::canonicalize(&binary_path),
        ) {
            (Ok(a), Ok(b)) => a == b,
            _ => current_exe == binary_path,
        }
    });

    let current_version = env!("CARGO_PKG_VERSION");

    let (installed_version, relation) = if running_from_installed {
        (Some(current_version.to_string()), VersionRelation::Same)
    } else {
        let installed = probe_binary_version(&binary_path);
        let rel = installed.as_deref().map_or(VersionRelation::Unknown, |v| {
            compare_versions(current_version, v)
        });
        (installed, rel)
    };

    Some(InstalledInfo {
        binary_path,
        installed_version,
        current_version,
        relation,
        running_from_installed,
    })
}

/// Extracts and normalizes a semantic version (`X.Y.Z`) from `vdpi --version` stdout.
pub fn parse_version_from_cli_output(stdout: &str) -> Option<String> {
    let first_line = stdout.lines().find(|line| !line.trim().is_empty())?;
    first_line.split_whitespace().find_map(|token| {
        let (major, minor, patch) =
            parse_semver(token).or_else(|| token.strip_prefix('v').and_then(parse_semver))?;
        Some(format!("{major}.{minor}.{patch}"))
    })
}

fn probe_binary_version(path: &Path) -> Option<String> {
    const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
    const POLL_INTERVAL: Duration = Duration::from_millis(25);
    const MAX_PROBE_STDOUT_BYTES: usize = 4 * 1024;

    let mut cmd = Command::new(path);
    cmd.arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd.spawn().ok()?;
    let stdout_pipe = child.stdout.take()?;

    let reader_handle = std::thread::spawn(move || {
        let mut pipe = stdout_pipe;
        let mut retained = Vec::new();
        let mut scratch = [0u8; 1024];
        loop {
            match pipe.read(&mut scratch) {
                Ok(0) => break,
                Ok(n) => {
                    if retained.len() < MAX_PROBE_STDOUT_BYTES {
                        let keep = (MAX_PROBE_STDOUT_BYTES - retained.len()).min(n);
                        retained.extend_from_slice(&scratch[..keep]);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        retained
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if start.elapsed() >= PROBE_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };

    let raw_stdout = reader_handle.join().ok()?;
    let status = status?;
    if !status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&raw_stdout);
    parse_version_from_cli_output(&stdout)
}

pub fn launch_agent_plist_path() -> Result<PathBuf> {
    Ok(home_dir()?
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LAUNCH_AGENT_LABEL}.plist")))
}

pub fn systemd_user_unit_path() -> Result<PathBuf> {
    let config_base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            home_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".config")
        });
    Ok(config_base
        .join("systemd")
        .join("user")
        .join(SYSTEMD_UNIT_NAME))
}

pub fn build_windows_service_bin_path(bin_path: &Path, cfg: &RuntimeConfig) -> String {
    let mut args = vec!["--service".to_string()];
    args.extend(build_service_cli_args(cfg));
    args.push("--quiet".to_string());
    let quoted_args: Vec<String> = args.into_iter().map(|a| quote_windows_arg(&a)).collect();
    format!("\"{}\" {}", bin_path.display(), quoted_args.join(" "))
}

pub(crate) fn quote_windows_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }

    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                for _ in 0..(backslashes * 2 + 1) {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            c => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(c);
            }
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

pub fn build_service_cli_args(cfg: &RuntimeConfig) -> Vec<String> {
    let mut args = vec![
        "--bind".to_string(),
        cfg.addr.to_string(),
        "--port".to_string(),
        cfg.port.to_string(),
        "--chunk-size".to_string(),
        cfg.chunk_size.to_string(),
    ];

    if let Some(sp) = cfg.socks_port {
        args.push("--socks-port".to_string());
        args.push(sp.to_string());
    } else {
        args.push("--socks-port".to_string());
        args.push("0".to_string());
    }

    if !cfg.enable_doh {
        args.push("--no-doh".to_string());
    }

    if cfg.mode != DesyncMode::Combo {
        let mode_str = match cfg.mode {
            DesyncMode::Combo => "combo",
            DesyncMode::TlsRecord => "tls-record",
            DesyncMode::Fragment => "fragment",
            DesyncMode::Split => "split",
        };
        args.push("--mode".to_string());
        args.push(mode_str.to_string());
    }

    if cfg.dns_addr != "1.1.1.1" {
        args.push("--dns".to_string());
        args.push(cfg.dns_addr.clone());
    }
    if cfg.dns_port != 53 {
        args.push("--dns-port".to_string());
        args.push(cfg.dns_port.to_string());
    }
    if cfg.dns_ipv4_only {
        args.push("--ipv4-only".to_string());
    }
    if cfg.connect_timeout != std::time::Duration::from_secs(8) {
        args.push("--timeout".to_string());
        args.push(cfg.connect_timeout.as_millis().to_string());
    }
    if !cfg.system_proxy {
        args.push("--no-system-proxy".to_string());
    } else {
        if !cfg.socks_system_proxy && cfg.socks_port.is_some() {
            args.push("--no-socks-proxy".to_string());
        }
        if !cfg.env_proxy {
            args.push("--no-env-proxy".to_string());
        }
    }
    if !cfg.block_quic {
        args.push("--allow-quic".to_string());
    }
    for pattern in &cfg.patterns {
        args.push("--include".to_string());
        args.push(pattern.clone());
    }
    for domain in &cfg.bypass_domains {
        args.push("--bypass".to_string());
        args.push(domain.clone());
    }
    if cfg.debug {
        args.push("--debug".to_string());
    }

    args
}

pub fn generate_launch_agent_plist(bin_path: &Path, cfg: &RuntimeConfig) -> String {
    let log_dir = vdpi_root_dir()
        .map(|r| r.join("logs"))
        .unwrap_or_else(|_| PathBuf::from("/tmp"));
    let out_log = log_dir.join("vdpi.out.log");
    let err_log = log_dir.join("vdpi.err.log");

    let mut args = vec![bin_path.display().to_string()];
    args.extend(build_service_cli_args(cfg));

    let args_xml: String = args
        .iter()
        .map(|a| format!("        <string>{}</string>", xml_escape(a)))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
{args_xml}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>{out_log}</string>
    <key>StandardErrorPath</key>
    <string>{err_log}</string>
</dict>
</plist>
"#,
        label = LAUNCH_AGENT_LABEL,
        args_xml = args_xml,
        out_log = xml_escape(&out_log.display().to_string()),
        err_log = xml_escape(&err_log.display().to_string()),
    )
}

fn quote_systemd_arg(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for ch in raw.chars() {
        match ch {
            '\r' | '\n' | '\0' => {}
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str(r#"\""#),
            '%' => out.push_str("%%"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn generate_systemd_unit(bin_path: &Path, cfg: &RuntimeConfig) -> String {
    let bin_str = bin_path.display().to_string();
    let mut exec_parts = vec![quote_systemd_arg(&bin_str)];
    for arg in build_service_cli_args(cfg) {
        exec_parts.push(quote_systemd_arg(&arg));
    }
    let exec_start = exec_parts.join(" ");
    format!(
        "[Unit]\n\
Description=vdpi Anti-DPI Local Proxy Engine\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart={exec_start}\n\
KillMode=mixed\n\
Restart=always\n\
RestartSec=2\n\
LimitNOFILE=65536\n\
\n\
[Install]\n\
WantedBy=default.target\n"
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Installs the `vdpi` binary into the service directory and registers automatic
/// background startup for the active operating system (macOS LaunchAgent, native Windows
/// Service under SCM, or Linux systemd user unit).
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn install_service(_cfg: &RuntimeConfig) -> Result<()> {
    bail!(
        "service installation is not supported on {}",
        platform_name()
    );
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
pub fn install_service(cfg: &RuntimeConfig) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows::{broadcast_environment_change, notify_wininet_refresh};
        use crate::platform::windows_service::{is_elevated, relaunch_elevated_and_wait};

        if !is_elevated() {
            println!("Requesting Administrator privileges to install the vdpi Windows service...");
            let mut args = vec!["install".to_string()];
            args.extend(build_service_cli_args(cfg));
            relaunch_elevated_and_wait(&args)?;
            notify_wininet_refresh();
            broadcast_environment_change();
            println!("Installed and started Windows service: {WINDOWS_SERVICE_NAME} (AUTO_START)");
            return Ok(());
        }

        // Stop existing Windows service and any legacy vdpi.exe processes before replacing the binary.
        let _ = crate::platform::windows_service::stop_windows_service_if_running()?;
        cleanup_legacy_windows_startup();
        stop_windows_foreground_daemons();
    }

    let vdpi_root = vdpi_root_dir()?;
    let bin_dir = vdpi_root.join("bin");
    let log_dir = vdpi_root.join("logs");
    fs::create_dir_all(&bin_dir)
        .with_context(|| format!("failed to create service directory {}", bin_dir.display()))?;
    fs::create_dir_all(&log_dir)
        .with_context(|| format!("failed to create log directory {}", log_dir.display()))?;

    let current_exe = std::env::current_exe().context("failed to determine current executable")?;
    let target_bin = installed_binary_path()?;

    let same_binary = match (
        fs::canonicalize(&current_exe),
        fs::canonicalize(&target_bin),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => current_exe == target_bin,
    };

    if !same_binary {
        let tmp_name = if cfg!(windows) {
            format!("vdpi.tmp.{}.exe", std::process::id())
        } else {
            format!(".vdpi.tmp.{}", std::process::id())
        };
        let tmp_bin = bin_dir.join(tmp_name);
        if let Err(err) = fs::copy(&current_exe, &tmp_bin)
            .with_context(|| format!("failed to copy {:?} to {:?}", current_exe, tmp_bin))
        {
            let _ = fs::remove_file(&tmp_bin);
            return Err(err);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(err) = fs::set_permissions(&tmp_bin, fs::Permissions::from_mode(0o755)) {
                let _ = fs::remove_file(&tmp_bin);
                return Err(err)
                    .with_context(|| format!("failed to chmod 0755 {}", tmp_bin.display()));
            }
            #[cfg(target_os = "macos")]
            {
                let _ = Command::new("/usr/bin/codesign")
                    .args(["-fs", "-"])
                    .arg(&tmp_bin)
                    .output();
            }
            if let Err(err) = fs::rename(&tmp_bin, &target_bin) {
                let _ = fs::remove_file(&tmp_bin);
                return Err(err).with_context(|| {
                    format!(
                        "failed to atomically replace {} with {}",
                        target_bin.display(),
                        tmp_bin.display()
                    )
                });
            }
        }

        #[cfg(target_os = "windows")]
        {
            let backup_path = if target_bin.exists() {
                let preferred = bin_dir.join("vdpi.old.exe");
                let backup = if preferred.exists() && fs::remove_file(&preferred).is_err() {
                    bin_dir.join(format!("vdpi.old.{}.exe", std::process::id()))
                } else {
                    preferred
                };
                if let Err(err) = fs::rename(&target_bin, &backup) {
                    let _ = fs::remove_file(&tmp_bin);
                    return Err(err).with_context(|| {
                        format!(
                            "failed to move existing binary {} aside to {}",
                            target_bin.display(),
                            backup.display()
                        )
                    });
                }
                Some(backup)
            } else {
                None
            };

            if let Err(err) = fs::rename(&tmp_bin, &target_bin) {
                let _ = fs::remove_file(tmp_bin);
                if let Some(backup) = backup_path {
                    let _ = fs::rename(backup, &target_bin);
                }
                return Err(err).with_context(|| {
                    format!("failed to install new binary to {}", target_bin.display())
                });
            }

            if let Some(backup) = backup_path {
                let _ = fs::remove_file(backup);
            }
        }
    }

    #[cfg(target_os = "macos")]
    install_macos_launch_agent(&target_bin, cfg)?;

    #[cfg(target_os = "linux")]
    install_linux_systemd_service(&target_bin, cfg)?;

    #[cfg(target_os = "windows")]
    install_windows_native_service(&target_bin, cfg)?;

    Ok(())
}

#[cfg(target_os = "macos")]
fn install_macos_launch_agent(target_bin: &Path, cfg: &RuntimeConfig) -> Result<()> {
    let uid = current_uid();
    let domain_target = format!("gui/{uid}");
    let plist_path = launch_agent_plist_path()?;
    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent)?;
    }

    if plist_path.exists() {
        let _ = Command::new("/bin/launchctl")
            .args(["bootout", &domain_target, &plist_path.display().to_string()])
            .output();
    }

    let plist_xml = generate_launch_agent_plist(target_bin, cfg);
    fs::write(&plist_path, plist_xml)?;

    let boot = Command::new("/bin/launchctl")
        .args([
            "bootstrap",
            &domain_target,
            &plist_path.display().to_string(),
        ])
        .output()?;
    if !boot.status.success() {
        let fallback = Command::new("/bin/launchctl")
            .args(["load", "-w", &plist_path.display().to_string()])
            .output()?;
        if !fallback.status.success() {
            bail!(
                "failed to load LaunchAgent {}: {}",
                plist_path.display(),
                String::from_utf8_lossy(&fallback.stderr).trim()
            );
        }
    }

    let _ = Command::new("/bin/launchctl")
        .args([
            "kickstart",
            "-k",
            &format!("{domain_target}/{LAUNCH_AGENT_LABEL}"),
        ])
        .output();

    let path_updated = ensure_unix_shell_path();

    println!("Installed binary : {}", target_bin.display());
    println!("Loaded service   : {}", plist_path.display());
    if path_updated {
        println!("Shell PATH       : added ~/.vdpi/bin (restart shell or source profile)");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_linux_systemd_service(target_bin: &Path, cfg: &RuntimeConfig) -> Result<()> {
    if let Ok(home) = home_dir() {
        let local_bin = home.join(".local").join("bin");
        if fs::create_dir_all(&local_bin).is_ok() {
            let link_path = local_bin.join("vdpi");
            let _ = fs::remove_file(&link_path);
            let _ = std::os::unix::fs::symlink(target_bin, link_path);
        }
    }

    let unit_path = systemd_user_unit_path()?;
    if let Some(parent) = unit_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let unit_text = generate_systemd_unit(target_bin, cfg);
    fs::write(&unit_path, unit_text)?;

    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();
    let enable = Command::new("systemctl")
        .args(["--user", "enable", SYSTEMD_UNIT_NAME])
        .output();

    let mut systemd_note = enable
        .ok()
        .filter(|out| !out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stderr).trim().to_string());

    if systemd_note.is_none() {
        let restart = Command::new("systemctl")
            .args(["--user", "restart", SYSTEMD_UNIT_NAME])
            .output();
        if let Some(out) = restart.ok().filter(|out| !out.status.success()) {
            systemd_note = Some(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
    }

    if let Some(reason) = systemd_note {
        println!(
            "Note: systemd user session not active ({reason}). Wrote unit file to {}",
            unit_path.display()
        );
    }

    let path_updated = ensure_unix_shell_path();

    println!("Installed binary : {}", target_bin.display());
    println!("Systemd unit     : {}", unit_path.display());
    if path_updated {
        println!("Shell PATH       : added ~/.vdpi/bin (restart shell or source profile)");
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn ensure_unix_shell_path() -> bool {
    let Ok(home) = home_dir() else {
        return false;
    };
    let export_line = r#"export PATH="$HOME/.vdpi/bin:$PATH""#;
    let mut updated = false;
    for rc_name in [".zshrc", ".bashrc", ".profile"] {
        let rc_path = home.join(rc_name);
        if !rc_path.is_file() {
            continue;
        }
        let Ok(content) = fs::read_to_string(&rc_path) else {
            continue;
        };
        if content.contains(".vdpi/bin") {
            continue;
        }
        let mut next = content;
        if !next.ends_with('\n') {
            next.push('\n');
        }
        next.push_str(export_line);
        next.push('\n');
        if fs::write(&rc_path, next).is_ok() {
            updated = true;
        }
    }
    updated
}

#[cfg(target_os = "windows")]
fn install_windows_native_service(target_bin: &Path, cfg: &RuntimeConfig) -> Result<()> {
    use crate::platform::windows::{
        add_dir_to_windows_system_path, broadcast_environment_change, notify_wininet_refresh,
    };
    use crate::platform::windows_service::install_or_update_windows_service;

    let bin_path_cmd = build_windows_service_bin_path(target_bin, cfg);
    install_or_update_windows_service(&bin_path_cmd)?;

    let legacy_bin = legacy_windows_root_dir().map(|r| r.join("bin"));
    let path_added = target_bin
        .parent()
        .and_then(|bin_dir| add_dir_to_windows_system_path(bin_dir, legacy_bin.as_deref()).ok())
        .unwrap_or(false);

    // Refresh WinINET and environment directly in the interactive caller's session as well.
    notify_wininet_refresh();
    broadcast_environment_change();

    println!("Installed binary : {}", target_bin.display());
    println!("Windows service  : {WINDOWS_SERVICE_NAME} (AUTO_START, RUNNING)");
    if path_added {
        if let Some(bin_dir) = target_bin.parent() {
            println!("System PATH      : added {}", bin_dir.display());
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn legacy_windows_root_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|p| PathBuf::from(p).join("vdpi"))
}

#[cfg(target_os = "windows")]
fn cleanup_legacy_windows_startup() {
    use crate::platform::windows::run_reg;

    let _ = run_reg(&["delete", WINDOWS_LEGACY_RUN_KEY, "/v", "vdpi", "/f"]);
    if let Some(legacy_root) = legacy_windows_root_dir() {
        let legacy_vbs = legacy_root.join("bin").join("vdpi-autostart.vbs");
        let _ = fs::remove_file(legacy_vbs);
    }
}

#[cfg(target_os = "windows")]
fn stop_windows_foreground_daemons() {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let my_pid = std::process::id();
    // Stop published daemon PIDs only; the unelevated installer is waiting for our exit.
    for state in read_runtime_states() {
        if state.pid != my_pid {
            let _ = Command::new("taskkill")
                .creation_flags(CREATE_NO_WINDOW)
                .args([
                    "/F",
                    "/PID",
                    &state.pid.to_string(),
                    "/FI",
                    "IMAGENAME eq vdpi.exe",
                ])
                .output();
        }
    }
}

#[cfg(target_os = "windows")]
fn cleanup_windows_install_files() {
    use crate::platform::windows::remove_dir_from_windows_path;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let Ok(vdpi_root) = vdpi_root_dir() else {
        return;
    };
    let bin_dir = vdpi_root.join("bin");
    let legacy_root = legacy_windows_root_dir();
    let legacy_bin = legacy_root.as_ref().map(|r| r.join("bin"));

    remove_dir_from_windows_path(&bin_dir, legacy_bin.as_deref());

    let current_exe = std::env::current_exe()
        .ok()
        .and_then(|p| fs::canonicalize(&p).ok());

    if let Some(ref legacy) = legacy_root {
        let running_from_legacy = current_exe
            .as_ref()
            .zip(fs::canonicalize(legacy).ok())
            .is_some_and(|(exe, root)| exe.starts_with(root));
        if legacy.exists() && !running_from_legacy {
            let _ = fs::remove_dir_all(legacy);
        }
    }

    let pd_dir = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("vdpi");
    if pd_dir.exists() {
        let _ = fs::remove_dir_all(&pd_dir);
    }

    if vdpi_root.exists() {
        let running_from_root = current_exe
            .as_ref()
            .zip(fs::canonicalize(&vdpi_root).ok())
            .is_some_and(|(exe, root)| exe.starts_with(root));
        if running_from_root {
            let _ = fs::remove_dir_all(vdpi_root.join("logs"));
            // Schedule silent removal of the install folder right after this process exits.
            let cleanup_cmd = format!(
                "timeout /t 1 /nobreak >nul & rmdir /S /Q \"{}\"",
                vdpi_root.display()
            );
            let _ = Command::new("cmd.exe")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["/C", &cleanup_cmd])
                .spawn();
        } else {
            let _ = fs::remove_dir_all(&vdpi_root);
        }
    }
}

/// Stops the background service, removes startup registration, cleans installed files,
/// and restores system proxy state.
pub fn uninstall_service() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let uid = current_uid();
        let domain_target = format!("gui/{uid}");
        let plist_path = launch_agent_plist_path()?;

        if plist_path.exists() {
            let _ = Command::new("/bin/launchctl")
                .args(["bootout", &domain_target, &plist_path.display().to_string()])
                .output();
            let _ = Command::new("/bin/launchctl")
                .args(["unload", &plist_path.display().to_string()])
                .output();
            fs::remove_file(&plist_path)?;
            println!("Removed LaunchAgent: {}", plist_path.display());
        } else {
            println!("LaunchAgent {} is not installed", plist_path.display());
        }
        if let Ok(root) = vdpi_root_dir() {
            if root.exists() {
                let _ = fs::remove_dir_all(&root);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let unit_path = systemd_user_unit_path()?;
        let _ = Command::new("systemctl")
            .args(["--user", "disable", "--now", SYSTEMD_UNIT_NAME])
            .output();
        if unit_path.exists() {
            fs::remove_file(&unit_path)?;
            let _ = Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .output();
            println!("Removed systemd user unit: {}", unit_path.display());
        } else {
            println!("Systemd unit {} is not installed", unit_path.display());
        }
        if let Ok(home) = home_dir() {
            let _ = fs::remove_file(home.join(".local").join("bin").join("vdpi"));
        }
        if let Ok(root) = vdpi_root_dir() {
            if root.exists() {
                let _ = fs::remove_dir_all(&root);
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows_service::{is_elevated, relaunch_elevated_and_wait};

        if !is_elevated() {
            println!(
                "Requesting Administrator privileges to uninstall the vdpi Windows service..."
            );
            relaunch_elevated_and_wait(&["uninstall".to_string()])?;
            clear_all_system_proxies()?;
            println!(
                "Removed Windows service '{WINDOWS_SERVICE_NAME}' and restored {} system proxy settings.",
                platform_name()
            );
            return Ok(());
        }

        let removed = crate::platform::windows_service::uninstall_windows_service()?;
        cleanup_legacy_windows_startup();
        stop_windows_foreground_daemons();
        if removed {
            println!("Stopped and removed Windows service: {WINDOWS_SERVICE_NAME}");
        } else {
            println!("Windows service '{WINDOWS_SERVICE_NAME}' is not installed.");
        }
    }

    clear_all_system_proxies()?;

    #[cfg(target_os = "windows")]
    cleanup_windows_install_files();

    println!("Restored {} system proxy settings.", platform_name());
    Ok(())
}

async fn discover_live_daemon(
    client: &Client,
    cfg: &RuntimeConfig,
) -> (IpAddr, u16, Option<u16>, Option<String>) {
    let states = read_runtime_states();

    let primary_socket = SocketAddr::new(cfg.addr, cfg.port);
    let primary_url = format!("http://{primary_socket}/vdpi-health");
    if let Ok(resp) = client.get(primary_url).send().await {
        if resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            let matching_socks = states
                .iter()
                .find(|s| s.addr == cfg.addr && s.port == cfg.port)
                .map(|s| s.socks_port)
                .unwrap_or(cfg.socks_port);
            return (cfg.addr, cfg.port, matching_socks, Some(text));
        }
    }

    for st in states {
        if st.addr == cfg.addr && st.port == cfg.port {
            continue;
        }
        let state_socket = SocketAddr::new(st.addr, st.port);
        let url = format!("http://{state_socket}/vdpi-health");
        if let Ok(resp) = client.get(url).send().await {
            if resp.status().is_success() {
                let text = resp.text().await.unwrap_or_default();
                return (st.addr, st.port, st.socks_port, Some(text));
            }
        }
    }

    (cfg.addr, cfg.port, cfg.socks_port, None)
}

/// Prints a comprehensive status overview of `vdpi`, startup service registration, and OS proxies.
pub async fn print_status(cfg: &RuntimeConfig) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()?;

    let (active_addr, active_port, active_socks_port, health_body) =
        discover_live_daemon(&client, cfg).await;

    let daemon_state = match health_body {
        Some(text) => format!("RUNNING ({})", text.trim()),
        None => "NOT RESPONDING".to_string(),
    };

    let socks_state = if let Some(sp) = active_socks_port {
        match tokio::time::timeout(
            Duration::from_secs(1),
            tokio::net::TcpStream::connect((active_addr, sp)),
        )
        .await
        {
            Ok(Ok(_)) => format!("LISTENING ({}:{})", active_addr, sp),
            _ => format!("CLOSED ({}:{})", active_addr, sp),
        }
    } else {
        "DISABLED (available via primary port auto-detect)".to_string()
    };

    println!("=== vdpi status ({}) ===", platform_name());
    println!(
        "Primary HTTP/CONNECT/Auto : {}:{} -> {}",
        active_addr, active_port, daemon_state
    );
    println!("Dedicated SOCKS5 (TCP/UDP): {}", socks_state);

    #[cfg(target_os = "macos")]
    {
        let plist_path = launch_agent_plist_path()?;
        println!(
            "LaunchAgent plist         : {} ({})",
            plist_path.display(),
            if plist_path.exists() {
                "installed"
            } else {
                "not installed"
            }
        );
    }

    #[cfg(target_os = "linux")]
    {
        let unit_path = systemd_user_unit_path()?;
        println!(
            "systemd user unit         : {} ({})",
            unit_path.display(),
            if unit_path.exists() {
                "installed"
            } else {
                "not installed"
            }
        );
    }

    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows::query_reg_sz;
        use crate::platform::windows_service::query_windows_service_status;

        let svc = query_windows_service_status();
        if svc.installed {
            let pid_suffix = svc.pid.map(|p| format!(", PID {p}")).unwrap_or_default();
            println!(
                "Windows Service ({WINDOWS_SERVICE_NAME})    : {} ({}{})",
                svc.state, svc.start_type, pid_suffix
            );
            if let Some(bin) = svc.binary_path {
                println!("Service Command           : {bin}");
            }
        } else {
            println!("Windows Service ({WINDOWS_SERVICE_NAME})    : NOT INSTALLED");
        }

        if let Some(legacy) = query_reg_sz(WINDOWS_LEGACY_RUN_KEY, "vdpi") {
            println!("Legacy Startup (HKCU Run) : {legacy} (run 'vdpi install' to migrate)");
        }
    }

    print_platform_proxy_status();
    Ok(())
}

/// Runs live end-to-end connectivity checks through `vdpi` (spawning an ephemeral in-process
/// engine if `vdpi` is not yet listening on `cfg.port`) against Discord and Roblox endpoints.
pub async fn run_doctor(cfg: RuntimeConfig) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let direct_check = Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(800))
        .build()?;

    let (active_addr, active_port, active_socks_port, live_health) =
        discover_live_daemon(&direct_check, &cfg).await;

    let (http_proxy_addr, socks_proxy_addr, _guard_tx) = if live_health.is_some() {
        let hp = SocketAddr::new(active_addr, active_port);
        let sp = SocketAddr::new(active_addr, active_socks_port.unwrap_or(active_port));
        println!("Testing against running vdpi daemon at {hp} (SOCKS5: {sp})...\n");
        (hp, sp, None)
    } else {
        let mut ephemeral_cfg = cfg.clone();
        ephemeral_cfg.port = 0;
        ephemeral_cfg.socks_port = Some(0);
        ephemeral_cfg.system_proxy = false;
        let ctx = EngineContext::new(ephemeral_cfg)?;
        let bound = crate::server::bind_listeners(&ctx)?;
        let hp = bound.primary_addr;
        let sp = bound.socks_addr.unwrap_or(hp);
        let (tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            let _ = crate::server::serve_until_shutdown(bound, ctx, rx).await;
        });
        println!("Testing with ephemeral in-process vdpi engine at {hp} (SOCKS5: {sp})...\n");
        (hp, sp, Some(tx))
    };

    let http_client = Client::builder()
        .proxy(Proxy::all(format!("http://{http_proxy_addr}"))?)
        .timeout(Duration::from_secs(8))
        .build()?;

    let discord_updater_url = if cfg!(target_os = "windows") {
        "https://updates.discord.com/distributions/app/manifests/latest?channel=stable&platform=win&arch=x64"
    } else if cfg!(target_os = "linux") {
        "https://updates.discord.com/distributions/app/manifests/latest?channel=stable&platform=linux&arch=x64"
    } else if cfg!(target_arch = "aarch64") {
        "https://updates.discord.com/distributions/app/manifests/latest?channel=stable&platform=osx&arch=arm64"
    } else {
        "https://updates.discord.com/distributions/app/manifests/latest?channel=stable&platform=osx&arch=x64"
    };

    let roblox_settings_url = if cfg!(target_os = "windows") {
        "https://clientsettingscdn.roblox.com/v2/client-version/WindowsPlayer"
    } else {
        "https://clientsettingscdn.roblox.com/v2/client-version/MacPlayer"
    };

    let targets = [
        ("Discord Web", "https://discord.com"),
        ("Discord Updater", discord_updater_url),
        ("Discord Gateway", "https://gateway.discord.gg"),
        ("Discord CDN", "https://cdn.discordapp.com"),
        ("Discord Voice Latency", "https://latency.discord.media"),
        ("Roblox Web", "https://www.roblox.com"),
        ("Roblox ClientSettings", roblox_settings_url),
        ("Roblox APIs", "https://apis.roblox.com"),
        ("Roblox Auth", "https://auth.roblox.com"),
        ("Roblox GameJoin", "https://gamejoin.roblox.com"),
        ("Roblox Telemetry", "https://ecsv2.roblox.com"),
    ];

    let mut passed = 0usize;
    println!("=== HTTP/HTTPS CONNECT Tunnel Checks ===");
    for (label, url) in targets {
        let t0 = Instant::now();
        match http_client.get(url).send().await {
            Ok(resp) => {
                let ms = t0.elapsed().as_millis();
                println!(
                    "  [PASS] {:24} -> HTTP {:3} ({:4} ms)",
                    label,
                    resp.status().as_u16(),
                    ms
                );
                passed += 1;
            }
            Err(e) => {
                println!("  [FAIL] {:24} -> {}", label, e);
            }
        }
    }

    println!("\n=== SOCKS5h (Remote DoH + TLS DPI Desync) Checks ===");
    let socks_client = Client::builder()
        .proxy(Proxy::all(format!("socks5h://{socks_proxy_addr}"))?)
        .timeout(Duration::from_secs(8))
        .build()?;

    let mut socks_ok = true;
    for (label, url) in [
        ("SOCKS5 Discord", "https://discord.com"),
        ("SOCKS5 Discord Gateway", "https://gateway.discord.gg"),
        ("SOCKS5 Roblox Web", "https://www.roblox.com"),
        ("SOCKS5 Roblox APIs", "https://apis.roblox.com"),
    ] {
        let t0 = Instant::now();
        match socks_client.get(url).send().await {
            Ok(resp) => {
                println!(
                    "  [PASS] {:24} -> HTTP {:3} ({:4} ms)",
                    label,
                    resp.status().as_u16(),
                    t0.elapsed().as_millis()
                );
            }
            Err(e) => {
                println!("  [FAIL] {:24} -> {}", label, e);
                socks_ok = false;
            }
        }
    }

    if passed != targets.len() || !socks_ok {
        bail!(
            "doctor detected failures ({}/{} HTTP passed, socks5_ok={})",
            passed,
            targets.len(),
            socks_ok
        );
    }

    println!("\nAll Discord & Roblox HTTP CONNECT and SOCKS5h checks passed.");
    Ok(())
}

#[cfg(target_os = "macos")]
fn current_uid() -> u32 {
    unsafe {
        extern "C" {
            fn getuid() -> u32;
        }
        getuid()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliArgs;

    #[test]
    fn generates_valid_service_manifests_for_all_platforms() {
        let cli = CliArgs::parse_from_iter(["vdpi", "--chunk-size", "10"]).unwrap();
        let cfg = cli.into_runtime_config();

        let plist = generate_launch_agent_plist(Path::new("/Users/test/.vdpi/bin/vdpi"), &cfg);
        assert!(plist.contains("<string>com.vdpi</string>"));
        assert!(plist.contains("<string>--chunk-size</string>"));
        assert!(plist.contains("<string>10</string>"));
        assert!(plist.contains("<string>--socks-port</string>"));
        assert!(plist.contains("<string>1080</string>"));

        let unit = generate_systemd_unit(Path::new("/home/test/.vdpi/bin/vdpi"), &cfg);
        assert!(unit.contains("ExecStart=\"/home/test/.vdpi/bin/vdpi\""));
        assert!(unit.contains("LimitNOFILE=65536"));

        let win_bin =
            build_windows_service_bin_path(Path::new(r"C:\Program Files\vdpi\bin\vdpi.exe"), &cfg);
        assert!(win_bin.starts_with(r#""C:\Program Files\vdpi\bin\vdpi.exe" --service "#));
        assert!(win_bin.contains("--bind 127.0.0.1"));
        assert!(win_bin.contains("--port 8080"));
        assert!(win_bin.contains("--chunk-size 10"));
        assert!(win_bin.contains("--socks-port 1080"));
        assert!(win_bin.contains("--quiet"));
    }

    #[test]
    fn preserves_custom_flags_in_windows_service_bin_path() {
        let cli = CliArgs::parse_from_iter([
            "vdpi",
            "--mode",
            "tls-record",
            "--dns",
            "8.8.8.8",
            "--bypass",
            "*.example.com",
            "--no-env-proxy",
        ])
        .unwrap();
        let cfg = cli.into_runtime_config();
        let win_bin =
            build_windows_service_bin_path(Path::new(r"C:\Program Files\vdpi\bin\vdpi.exe"), &cfg);
        assert!(win_bin.contains("--service"));
        assert!(win_bin.contains("--mode tls-record"));
        assert!(win_bin.contains("--dns 8.8.8.8"));
        assert!(win_bin.contains("--bypass *.example.com"));
        assert!(win_bin.contains("--no-env-proxy"));
    }

    #[test]
    fn parses_version_from_cli_output() {
        assert_eq!(
            parse_version_from_cli_output("vdpi 0.3.3\n").as_deref(),
            Some("0.3.3")
        );
        assert_eq!(
            parse_version_from_cli_output("vdpi 0.3.4\r\n").as_deref(),
            Some("0.3.4")
        );
        assert_eq!(
            parse_version_from_cli_output("vdpi v1.2.3\n").as_deref(),
            Some("1.2.3")
        );
        assert_eq!(
            parse_version_from_cli_output("0.3.4\n").as_deref(),
            Some("0.3.4")
        );
        assert_eq!(parse_version_from_cli_output(""), None);
        assert_eq!(parse_version_from_cli_output("   \r\n"), None);
        assert_eq!(parse_version_from_cli_output("garbage output\n"), None);
        assert_eq!(parse_version_from_cli_output("vdpi not-a-version\n"), None);
    }

    #[test]
    fn quotes_windows_args_with_backslashes_and_quotes() {
        assert_eq!(quote_windows_arg("simple"), "simple");
        assert_eq!(quote_windows_arg(""), r#""""#);
        assert_eq!(quote_windows_arg("a b"), r#""a b""#);
        assert_eq!(quote_windows_arg(r#"a"b"#), r#""a\"b""#);
        assert_eq!(quote_windows_arg(r#"a\"b"#), r#""a\\\"b""#);
        assert_eq!(
            quote_windows_arg(r"C:\Program Files\vdpi\"),
            r#""C:\Program Files\vdpi\\""#
        );
        assert_eq!(quote_windows_arg(r#"a\\""#), r#""a\\\\\"""#);
    }

    #[test]
    fn escapes_systemd_unit_execstart_arguments() {
        let mut cli = CliArgs::parse_from_iter(["vdpi"]).unwrap();
        cli.bypass_domains = vec![
            "evil\nExecStartPost=/bin/sh".to_string(),
            r#"100%"a\b"#.to_string(),
        ];
        let cfg = cli.into_runtime_config();
        let unit = generate_systemd_unit(Path::new("/home/u%1/my \"dir\"\\vdpi"), &cfg);

        assert!(!unit.contains("\nExecStartPost="));
        assert!(unit.contains(r#"ExecStart="/home/u%%1/my \"dir\"\\vdpi""#));
        assert!(unit.contains(r#""100%%\"a\\b""#));
    }
}
