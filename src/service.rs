use crate::config::RuntimeConfig;
use crate::desync::EngineContext;
use crate::platform::{clear_all_system_proxies, platform_name, print_platform_proxy_status};
use anyhow::{bail, Context, Result};
use reqwest::{Client, Proxy};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

pub const LAUNCH_AGENT_LABEL: &str = "com.vdpi";
pub const SYSTEMD_UNIT_NAME: &str = "vdpi.service";
pub const WINDOWS_RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

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
        if let Some(local_appdata) = std::env::var_os("LOCALAPPDATA") {
            return Ok(PathBuf::from(local_appdata).join("vdpi"));
        }
    }
    Ok(home_dir()?.join(".vdpi"))
}

pub fn installed_binary_path() -> Result<PathBuf> {
    let bin_name = if cfg!(windows) { "vdpi.exe" } else { "vdpi" };
    Ok(vdpi_root_dir()?.join("bin").join(bin_name))
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

pub fn windows_autostart_vbs_path() -> Result<PathBuf> {
    Ok(vdpi_root_dir()?.join("bin").join("vdpi-autostart.vbs"))
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

pub fn generate_systemd_unit(bin_path: &Path, cfg: &RuntimeConfig) -> String {
    let args = build_service_cli_args(cfg).join(" ");
    format!(
        "[Unit]\n\
Description=vdpi Anti-DPI Local Proxy Engine\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart=\"{}\" {}\n\
Restart=always\n\
RestartSec=2\n\
LimitNOFILE=65536\n\
\n\
[Install]\n\
WantedBy=default.target\n",
        bin_path.display(),
        args
    )
}

pub fn generate_windows_autostart_vbs(bin_path: &Path, cfg: &RuntimeConfig) -> String {
    let mut args = build_service_cli_args(cfg);
    args.push("--quiet".to_string());
    let joined_args = args.join(" ");
    let escaped_bin = bin_path.display().to_string().replace('"', "\"\"");
    format!(
        "Set WshShell = CreateObject(\"WScript.Shell\")\r\n\
WshShell.Run \"\"\"{}\"\" {}\", 0, False\r\n",
        escaped_bin, joined_args
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Installs the `vdpi` binary into the user service directory and registers automatic
/// background startup for the active operating system (macOS LaunchAgent, Windows Registry Run,
/// or Linux systemd user unit).
pub fn install_service(cfg: &RuntimeConfig) -> Result<()> {
    let vdpi_root = vdpi_root_dir()?;
    let bin_dir = vdpi_root.join("bin");
    let log_dir = vdpi_root.join("logs");
    fs::create_dir_all(&bin_dir)?;
    fs::create_dir_all(&log_dir)?;

    let current_exe = std::env::current_exe().context("failed to determine current executable")?;
    let target_bin = installed_binary_path()?;

    if current_exe != target_bin {
        let tmp_name = if cfg!(windows) {
            "vdpi.tmp.exe"
        } else {
            "vdpi.tmp"
        };
        let tmp_bin = bin_dir.join(tmp_name);
        fs::copy(&current_exe, &tmp_bin)
            .with_context(|| format!("failed to copy {:?} to {:?}", current_exe, tmp_bin))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp_bin, fs::Permissions::from_mode(0o755))?;
        }
        #[cfg(target_os = "macos")]
        {
            let _ = Command::new("/usr/bin/codesign")
                .args(["-fs", "-", &tmp_bin.display().to_string()])
                .output();
        }
        let _ = fs::remove_file(&target_bin);
        fs::rename(&tmp_bin, &target_bin)?;
    }

    #[cfg(target_os = "macos")]
    install_macos_launch_agent(&target_bin, cfg)?;

    #[cfg(target_os = "linux")]
    install_linux_systemd_service(&target_bin, cfg)?;

    #[cfg(target_os = "windows")]
    install_windows_startup_service(&target_bin, cfg)?;

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

    println!("Installed binary : {}", target_bin.display());
    println!("Loaded service   : {}", plist_path.display());
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_linux_systemd_service(target_bin: &Path, cfg: &RuntimeConfig) -> Result<()> {
    if let Ok(home) = home_dir() {
        let local_bin = home.join(".local").join("bin");
        if fs::create_dir_all(&local_bin).is_ok() {
            let link_path = local_bin.join("vdpi");
            let _ = fs::remove_file(&link_path);
            #[cfg(unix)]
            let _ = std::os::unix::fs::symlink(target_bin, &link_path);
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
        .args(["--user", "enable", "--now", SYSTEMD_UNIT_NAME])
        .output();

    if let Ok(out) = enable {
        if !out.status.success() {
            println!(
                "Note: systemd user session not active ({}). Wrote unit file to {}",
                String::from_utf8_lossy(&out.stderr).trim(),
                unit_path.display()
            );
        }
    }

    println!("Installed binary : {}", target_bin.display());
    println!("Systemd unit     : {}", unit_path.display());
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_windows_startup_service(target_bin: &Path, cfg: &RuntimeConfig) -> Result<()> {
    use crate::platform::windows::run_reg;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let vbs_path = windows_autostart_vbs_path()?;
    let vbs_content = generate_windows_autostart_vbs(target_bin, cfg);
    fs::write(&vbs_path, vbs_content)?;

    let run_cmd = format!("wscript.exe //B \"{}\"", vbs_path.display());
    run_reg(&[
        "add",
        WINDOWS_RUN_KEY,
        "/v",
        "vdpi",
        "/t",
        "REG_SZ",
        "/d",
        &run_cmd,
        "/f",
    ])?;

    let my_pid = std::process::id();
    let _ = Command::new("taskkill")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["/F", "/FI", &format!("PID ne {my_pid}"), "/IM", "vdpi.exe"])
        .output();

    let _ = Command::new("wscript.exe")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["//B", &vbs_path.display().to_string()])
        .spawn();

    println!("Installed binary : {}", target_bin.display());
    println!("Startup launcher : {}", vbs_path.display());
    Ok(())
}

/// Stops the background service, removes startup registration, and restores system proxy state.
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
    }

    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows::run_reg;
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        let _ = run_reg(&["delete", WINDOWS_RUN_KEY, "/v", "vdpi", "/f"]);
        if let Ok(vbs) = windows_autostart_vbs_path() {
            let _ = fs::remove_file(vbs);
        }
        let my_pid = std::process::id();
        let _ = Command::new("taskkill")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/F", "/FI", &format!("PID ne {my_pid}"), "/IM", "vdpi.exe"])
            .output();
        println!("Removed Windows startup registration and stopped background vdpi.exe.");
    }

    clear_all_system_proxies()?;
    println!("Restored {} system proxy settings.", platform_name());
    Ok(())
}

/// Prints a comprehensive status overview of `vdpi`, startup service registration, and OS proxies.
pub async fn print_status(cfg: &RuntimeConfig) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let health_url = format!("http://{}:{}/vdpi-health", cfg.addr, cfg.port);
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()?;

    let daemon_state = match client.get(&health_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let text = resp.text().await.unwrap_or_default();
            format!("RUNNING ({})", text.trim())
        }
        _ => "NOT RESPONDING".to_string(),
    };

    let socks_state = if let Some(sp) = cfg.socks_port {
        match tokio::time::timeout(
            Duration::from_secs(1),
            tokio::net::TcpStream::connect((cfg.addr, sp)),
        )
        .await
        {
            Ok(Ok(_)) => format!("LISTENING ({}:{})", cfg.addr, sp),
            _ => format!("CLOSED ({}:{})", cfg.addr, sp),
        }
    } else {
        "DISABLED (available via primary port auto-detect)".to_string()
    };

    println!("=== vdpi status ({}) ===", platform_name());
    println!(
        "Primary HTTP/CONNECT/Auto : {}:{} -> {}",
        cfg.addr, cfg.port, daemon_state
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
        let reg_val =
            query_reg_sz(WINDOWS_RUN_KEY, "vdpi").unwrap_or_else(|| "not installed".into());
        println!("Windows Startup (HKCU Run): {reg_val}");
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
    let health_url = format!("http://{}:{}/vdpi-health", cfg.addr, cfg.port);

    let (http_proxy_addr, socks_proxy_addr, _guard_tx) =
        match direct_check.get(&health_url).send().await {
            Ok(r) if r.status().is_success() => {
                let hp = std::net::SocketAddr::new(cfg.addr, cfg.port);
                let sp = std::net::SocketAddr::new(cfg.addr, cfg.socks_port.unwrap_or(cfg.port));
                println!("Testing against running vdpi daemon at {hp} (SOCKS5: {sp})...\n");
                (hp, sp, None)
            }
            _ => {
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
                println!(
                    "Testing with ephemeral in-process vdpi engine at {hp} (SOCKS5: {sp})...\n"
                );
                (hp, sp, Some(tx))
            }
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

        let vbs = generate_windows_autostart_vbs(
            Path::new(r"C:\Users\test\AppData\Local\vdpi\bin\vdpi.exe"),
            &cfg,
        );
        assert!(vbs.contains("vdpi.exe"));
        assert!(vbs.contains("--quiet"));
    }
}
