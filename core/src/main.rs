use anyhow::Result;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::sync::watch;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use tracing::warn;
use tracing::{debug, info};
use vdpi::bypass::BypassPolicy;
use vdpi::config::{
    CliArgs, Command, ConfigCommand, EngineMode, RuntimeConfig, SplitCommand, SplitTunnelConfig,
    SplitTunnelMode,
};
use vdpi::config_file::{
    get_config_key, load_file_config, load_file_config_or_default, render_config_toml,
    save_file_config_atomic, set_config_key, system_config_path, unset_config_key,
    user_config_path, FileConfig, CONFIG_SCHEMA_VERSION,
};
use vdpi::desync::EngineContext;
use vdpi::platform::platform_name;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use vdpi::platform::unix_foreground as foreground;
#[cfg(windows)]
use vdpi::platform::windows::foreground;
use vdpi::server::{bind_listeners, serve_until_shutdown};
use vdpi::service::{
    clear_runtime_state, install_service, install_service_with_options, print_status, run_doctor,
    switch_service_engine, switch_service_engine_quiet, uninstall_service,
    uninstall_service_with_options, write_runtime_state, ServiceState,
};

mod launcher;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod tui_dashboard;

fn main() -> Result<()> {
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new(foreground::GUARD_ARG)) {
        return foreground::run_guard();
    }
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new(
            vdpi::platform::linux_tun::LINUX_TUN_CLEANUP_ARG,
        ))
    {
        return run_internal_linux_tun_cleanup();
    }
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new(
            vdpi::platform::macos_tun::MACOS_TUN_GUARD_ARG,
        ))
    {
        return run_internal_macos_tun_guard();
    }

    vdpi::update::cleanup_stale_old_binary();
    raise_fd_limit();

    let args: Vec<_> = std::env::args_os().collect();
    let bare = args.len() == 1;
    let raw_args: Vec<String> = args
        .iter()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let cli = CliArgs::parse_from_iter(args).unwrap_or_else(|e| e.exit());

    if cli.internal_linux_tun_cleanup {
        return run_internal_linux_tun_cleanup();
    }
    if cli.internal_macos_tun_guard {
        return run_internal_macos_tun_guard();
    }

    if let Some(Command::Config { action }) = cli.command.clone() {
        return handle_config_command(action, cli, &raw_args);
    }

    let resilient_admin_cmd = matches!(
        cli.command,
        Some(Command::Uninstall { .. } | Command::Pause | Command::Resume)
    );
    let (_loaded_config_path, file_cfg) = match load_file_config(
        cli.config_path.as_deref(),
        cli.service,
    ) {
        Ok(loaded) => loaded,
        Err(err) if resilient_admin_cmd => {
            eprintln!(
                    "Warning: ignoring invalid config.toml ({err:#}); continuing with built-in defaults"
                );
            (None, FileConfig::default())
        }
        Err(err) => return Err(err),
    };
    let mut command = cli.command.clone();
    let mut cfg = cli.resolve_runtime_config(&file_cfg, &raw_args);

    #[cfg(target_os = "windows")]
    if cfg.windows_service && matches!(command, Some(Command::Start) | None) {
        init_tracing(&cfg);
        return vdpi::platform::windows_service::run_windows_service(cfg);
    }

    #[cfg(not(target_os = "windows"))]
    if cfg.windows_service {
        anyhow::bail!("--service is only supported on Windows");
    }

    if bare || matches!(command, Some(Command::Launcher)) {
        let mut notice: Option<String> = None;
        let mut explicit_launcher = !bare;
        let mut cli_rt: Option<tokio::runtime::Runtime> = None;
        let mut session_engine_override: Option<EngineMode> = None;
        let mut session_dns_override: Option<String> = None;
        let mut session_split_override: Option<SplitTunnelConfig> = None;
        loop {
            let probe_status =
                |runtime_cfg: &RuntimeConfig, override_engine: Option<EngineMode>| {
                    let mut probed = vdpi::service::probe_control_center_status(runtime_cfg);
                    if let Some(eng) = override_engine {
                        if probed.installed.is_none()
                            && probed.service_state == ServiceState::NotInstalled
                            && probed.live_engine.is_none()
                        {
                            probed.configured_engine = eng;
                        }
                    }
                    probed
                };
            let initial_status = probe_status(&cfg, session_engine_override);
            let configured_dns = session_dns_override
                .clone()
                .unwrap_or_else(|| vdpi::service::load_configured_dns(&cfg.dns_addr));
            let configured_split = session_split_override
                .clone()
                .unwrap_or_else(vdpi::service::load_configured_split_tunnel);
            let latest_status = RefCell::new(initial_status.clone());
            let choice = launcher::choose_with_options(
                explicit_launcher,
                &initial_status,
                notice.as_deref(),
                &configured_dns,
                &configured_split,
                || {
                    let refreshed = probe_status(&cfg, session_engine_override);
                    *latest_status.borrow_mut() = refreshed.clone();
                    refreshed
                },
            )?;
            let status = latest_status.into_inner();
            let installed_before = status.installed.clone();
            match choice {
                launcher::Choice::Run => {
                    if status.service_state == ServiceState::Running || status.live_engine.is_some()
                    {
                        if cfg.engine == EngineMode::Tun {
                            notice = Some(
                                "Background service is already running. Pause it first before starting foreground TUN mode."
                                    .to_string(),
                            );
                            explicit_launcher = true;
                            continue;
                        } else if cfg.system_proxy {
                            notice = Some(
                                "Background service is already running. Pause it first or run with --no-system-proxy."
                                    .to_string(),
                            );
                            explicit_launcher = true;
                            continue;
                        }
                    }
                    #[cfg(target_os = "windows")]
                    if cfg.engine == EngineMode::Tun
                        && !vdpi::platform::windows_service::is_elevated()
                    {
                        match vdpi::platform::windows_service::relaunch_elevated_and_wait(&[
                            "--tun".to_string(),
                            "start".to_string(),
                        ]) {
                            Ok(()) => return Ok(()),
                            Err(err) => {
                                notice =
                                    Some(sanitize_notice(&format!("TUN start failed: {err:#}")));
                                explicit_launcher = true;
                                continue;
                            }
                        }
                    }
                    #[cfg(any(target_os = "macos", target_os = "linux"))]
                    if cfg.engine == EngineMode::Tun && !vdpi::service::is_unix_root() {
                        match vdpi::service::relaunch_unix_sudo_and_wait(
                            &["--tun".to_string(), "start".to_string()],
                            "run vdpi in TUN mode",
                        ) {
                            Ok(()) => return Ok(()),
                            Err(err) => {
                                notice =
                                    Some(sanitize_notice(&format!("TUN start failed: {err:#}")));
                                explicit_launcher = true;
                                continue;
                            }
                        }
                    }
                    if !cfg.quiet
                        && status.installed.is_none()
                        && status.service_state == ServiceState::NotInstalled
                    {
                        launcher::print_run_notice();
                    }
                    command = Some(Command::Start);
                    break;
                }
                launcher::Choice::Unattended => {
                    command = Some(Command::Start);
                    break;
                }
                launcher::Choice::Install => {
                    init_tracing(&cfg);
                    let result = install_service(&cfg);
                    launcher::install_finished(&result, installed_before.as_ref());
                    return result;
                }
                launcher::Choice::Update => {
                    init_tracing(&cfg);
                    let result = get_or_init_cli_runtime(&mut cli_rt)
                        .and_then(|rt| rt.block_on(vdpi::update::run_update(false, false, &cfg)));
                    launcher::update_finished(&result);
                    return result;
                }
                launcher::Choice::PauseService => {
                    match vdpi::service::pause_service_quiet() {
                        Ok(()) => {
                            notice = Some("Service paused - system proxies restored.".to_string());
                        }
                        Err(err) => {
                            notice = Some(sanitize_notice(&format!("Pause failed: {err:#}")));
                        }
                    }
                    explicit_launcher = true;
                }
                launcher::Choice::ResumeService => {
                    match vdpi::service::resume_service_quiet() {
                        Ok(()) => {
                            wait_for_live_engine(&cfg, status.configured_engine);
                            notice = Some("Service resumed - anti-DPI active.".to_string());
                        }
                        Err(err) => {
                            notice = Some(sanitize_notice(&format!("Resume failed: {err:#}")));
                        }
                    }
                    explicit_launcher = true;
                }
                launcher::Choice::SwitchEngine(target) => {
                    let is_installed = status.installed.is_some()
                        || status.service_state != ServiceState::NotInstalled;
                    if is_installed {
                        match switch_service_engine_quiet(target, &cfg) {
                            Ok(()) => {
                                cfg.engine = target;
                                session_engine_override = None;
                                if status.service_state == ServiceState::Running {
                                    wait_for_live_engine(&cfg, target);
                                }
                                let msg = match target {
                                    EngineMode::Tun => "Switched to TUN mode.",
                                    EngineMode::Proxy => "Switched to Proxy mode.",
                                };
                                notice = Some(msg.to_string());
                            }
                            Err(err) => {
                                notice = Some(sanitize_notice(&format!(
                                    "Engine switch failed: {err:#}"
                                )));
                            }
                        }
                    } else {
                        cfg.engine = target;
                        session_engine_override = Some(target);
                        let msg = match target {
                            EngineMode::Tun => "Engine set to TUN mode.",
                            EngineMode::Proxy => "Engine set to Proxy mode.",
                        };
                        notice = Some(msg.to_string());
                    }
                    explicit_launcher = true;
                }
                launcher::Choice::SelectDns => {
                    explicit_launcher = true;
                    continue;
                }
                launcher::Choice::SetDns(dns_addr) => {
                    let was_installed = status.installed.is_some()
                        || status.service_state != ServiceState::NotInstalled;
                    match vdpi::service::set_service_dns_quiet(dns_addr, &cfg) {
                        Ok(()) => {
                            cfg.dns_addr = dns_addr.to_string();
                            session_dns_override = Some(dns_addr.to_string());
                            let label = launcher::format_dns_label(dns_addr);
                            notice = Some(if was_installed {
                                format!("DNS server set to {label}.")
                            } else {
                                format!("DNS server set to {label} (saved).")
                            });
                        }
                        Err(err) => {
                            notice = Some(sanitize_notice(&format!("DNS change failed: {err:#}")));
                        }
                    }
                    explicit_launcher = true;
                    continue;
                }
                launcher::Choice::SplitTunnel => {
                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                    {
                        match vdpi::split_tunnel::tui::run_split_tunnel_picker(configured_split) {
                            Ok(Some(new_cfg)) => {
                                match vdpi::service::set_service_split_tunnel(&new_cfg) {
                                    Ok(msg) => {
                                        cfg.split_tunnel = new_cfg.clone();
                                        session_split_override = Some(new_cfg);
                                        notice = Some(sanitize_notice(&msg));
                                    }
                                    Err(err) => {
                                        notice = Some(sanitize_notice(&format!(
                                            "Split tunnel save failed: {err:#}"
                                        )));
                                    }
                                }
                            }
                            Ok(None) => {
                                notice = None;
                            }
                            Err(err) => {
                                notice = Some(sanitize_notice(&format!(
                                    "Split tunnel picker failed: {err:#}"
                                )));
                            }
                        }
                    }
                    #[cfg(any(target_os = "android", target_os = "ios"))]
                    {
                        notice = Some(
                            "Split tunnel picker is not supported on this platform.".to_string(),
                        );
                    }
                    explicit_launcher = true;
                    continue;
                }
                launcher::Choice::Dashboard => {
                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                    {
                        let result = get_or_init_cli_runtime(&mut cli_rt).and_then(|rt| {
                            rt.block_on(run_attached_dashboard_for_status(&status, &cfg))
                        });
                        match result {
                            Ok(true) => {
                                notice = None;
                            }
                            Ok(false) => {
                                notice = Some("No running vdpi service detected.".to_string());
                            }
                            Err(err) => {
                                notice =
                                    Some(sanitize_notice(&format!("Dashboard error: {err:#}")));
                            }
                        }
                    }
                    #[cfg(any(target_os = "android", target_os = "ios"))]
                    {
                        notice =
                            Some("Live dashboard is not supported on this platform.".to_string());
                    }
                    explicit_launcher = true;
                    continue;
                }
                launcher::Choice::Doctor => {
                    let result = get_or_init_cli_runtime(&mut cli_rt)
                        .and_then(|rt| rt.block_on(run_doctor(cfg.clone())));
                    notice = Some(match result {
                        Ok(()) => "Diagnostics complete.".to_string(),
                        Err(err) => {
                            eprintln!("\nDiagnostics error: {err:#}");
                            sanitize_notice(&format!("Diagnostics finished with issues: {err:#}"))
                        }
                    });
                    launcher::wait_for_continue_if_interactive();
                    explicit_launcher = true;
                }
                launcher::Choice::Uninstall => {
                    init_tracing(&cfg);
                    let result = uninstall_service();
                    launcher::uninstall_finished(&result);
                    return result;
                }
                launcher::Choice::Cancel => return Ok(()),
            }
        }
    }

    match command {
        Some(Command::Install { upgrade }) => {
            init_tracing(&cfg);
            install_service_with_options(&cfg, upgrade)?;
            launcher::clear_preference();
            Ok(())
        }
        Some(Command::Launcher) => unreachable!("handled by launcher"),
        Some(Command::Config { .. }) => unreachable!("handled by config command"),
        Some(Command::Uninstall { purge }) => {
            init_tracing(&cfg);
            uninstall_service_with_options(purge)?;
            launcher::clear_preference();
            Ok(())
        }
        Some(Command::Pause) => {
            init_tracing(&cfg);
            vdpi::service::pause_service()
        }
        Some(Command::Resume) => {
            init_tracing(&cfg);
            vdpi::service::resume_service()
        }
        Some(Command::Engine { mode }) => {
            init_tracing(&cfg);
            match mode {
                Some(target) => switch_service_engine(target, &cfg),
                None => {
                    let status = vdpi::service::probe_control_center_status(&cfg);
                    if let Some(live) = status.live_engine {
                        println!("{}", format_live_engine_line(&live));
                    } else {
                        println!("Engine: {} (configured)", status.configured_engine.as_str());
                    }
                    Ok(())
                }
            }
        }
        Some(Command::Dns { addr }) => {
            init_tracing(&cfg);
            match addr {
                Some(target) => vdpi::service::set_service_dns(&target, &cfg),
                None => {
                    let current = vdpi::service::load_configured_dns(&cfg.dns_addr);
                    println!("DNS: {}", launcher::format_dns_label(&current));
                    Ok(())
                }
            }
        }
        Some(Command::Dashboard) => handle_dashboard_command(&cfg),
        Some(Command::Split { action }) => handle_split_command(action),
        Some(Command::Status) | Some(Command::Doctor) | Some(Command::Update { .. }) => {
            init_tracing(&cfg);
            let rt = build_cli_runtime()?;
            rt.block_on(async move {
                match command {
                    Some(Command::Status) => print_status(&cfg).await,
                    Some(Command::Doctor) => run_doctor(cfg).await,
                    Some(Command::Update { check, force }) => {
                        vdpi::update::run_update(check, force, &cfg).await
                    }
                    _ => unreachable!(),
                }
            })
        }
        Some(Command::Start) | None => {
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            let dashboard_tracing =
                if tui_dashboard::should_enable_dashboard(&cfg, is_service_mode(&cfg)) {
                    Some(init_tui_tracing())
                } else {
                    init_tracing(&cfg);
                    None
                };
            #[cfg(any(target_os = "android", target_os = "ios"))]
            init_tracing(&cfg);
            let rt = build_runtime()?;
            rt.block_on(run_daemon(
                cfg,
                #[cfg(not(any(target_os = "android", target_os = "ios")))]
                dashboard_tracing,
            ))
        }
    }
}

fn run_internal_linux_tun_cleanup() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        vdpi::platform::linux_tun::cleanup_linux_tun_state()
    }
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("--internal-linux-tun-cleanup is only supported on Linux")
    }
}

fn run_internal_macos_tun_guard() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        vdpi::platform::macos_tun::run_macos_tun_cleanup_guard()
    }
    #[cfg(not(target_os = "macos"))]
    {
        anyhow::bail!("--internal-macos-tun-guard is only supported on macOS")
    }
}

fn resolve_config_path_for_display(explicit: Option<&Path>, service_mode: bool) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    if service_mode {
        #[cfg(target_os = "windows")]
        {
            return system_config_path();
        }
        #[cfg(not(target_os = "windows"))]
        {
            let sys = system_config_path();
            if sys.is_file() {
                return sys;
            }
            let usr = user_config_path();
            if usr.is_file() {
                return usr;
            }
            return sys;
        }
    }
    let usr = user_config_path();
    if usr.is_file() {
        return usr;
    }
    let sys = system_config_path();
    if sys.is_file() {
        return sys;
    }
    usr
}

fn is_process_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        vdpi::platform::windows_service::is_elevated()
    }
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(any(target_os = "windows", unix)))]
    {
        false
    }
}

fn resolve_writable_config_path(explicit: Option<&Path>, service_mode: bool) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if service_mode {
        return Ok(system_config_path());
    }
    let usr = user_config_path();
    if usr.is_file() {
        return Ok(usr);
    }
    let sys = system_config_path();
    if sys.is_file() {
        if is_process_elevated() {
            return Ok(sys);
        }
        #[cfg(target_os = "windows")]
        let hint = "Run this command from an elevated Administrator terminal to update the system config, or pass `--config <path>` to edit a separate file.";
        #[cfg(not(target_os = "windows"))]
        let hint = "Re-run with `sudo` to update the system config, or pass `--config <path>` to edit a separate file.";
        anyhow::bail!(
            "system configuration exists at {} and requires elevated privileges to modify. {hint}",
            sys.display()
        );
    }
    Ok(usr)
}

fn runtime_to_file_config(cfg: &RuntimeConfig) -> FileConfig {
    FileConfig {
        schema_version: Some(CONFIG_SCHEMA_VERSION),
        engine: Some(cfg.engine),
        mode: Some(cfg.mode),
        doh: Some(cfg.enable_doh),
        block_quic: Some(cfg.block_quic),
        dns_addr: Some(cfg.dns_addr.clone()),
        bypass_domains: Some(cfg.bypass_domains.clone()),
        include_domains: Some(cfg.patterns.clone()),
        split_tunnel_mode: Some(cfg.split_tunnel.mode),
        split_tunnel_apps: Some(cfg.split_tunnel.apps.clone()),
        vpn_coexistence: Some(cfg.vpn_coexistence),
        tun_ipv6: Some(cfg.tun_ipv6),
        chunk_size: Some(cfg.chunk_size),
        bind: Some(cfg.addr),
        port: Some(cfg.port),
        socks_port: Some(cfg.socks_port.unwrap_or(0)),
        dns_port: Some(cfg.dns_port),
        ipv4_only: Some(cfg.dns_ipv4_only),
        timeout_ms: Some(u64::try_from(cfg.connect_timeout.as_millis()).unwrap_or(u64::MAX)),
        system_proxy: Some(cfg.system_proxy),
        socks_system_proxy: Some(cfg.socks_system_proxy),
        env_proxy: Some(cfg.env_proxy),
    }
}

fn handle_config_command(
    action: Option<ConfigCommand>,
    cli: CliArgs,
    raw_args: &[String],
) -> Result<()> {
    let explicit_path = cli.config_path.clone();
    let service_mode = cli.service;

    match action.unwrap_or(ConfigCommand::Show { json: false }) {
        ConfigCommand::Show { json } => {
            let (loaded_path, file_cfg) = load_file_config(explicit_path.as_deref(), service_mode)?;
            let cfg = cli.resolve_runtime_config(&file_cfg, raw_args);
            if json {
                let payload = serde_json::json!({
                    "config_path": loaded_path.as_ref().map(|p| p.display().to_string()),
                    "engine": cfg.engine.as_str(),
                    "mode": cfg.mode,
                    "chunk_size": cfg.chunk_size,
                    "doh": cfg.enable_doh,
                    "block_quic": cfg.block_quic,
                    "dns_addr": cfg.dns_addr,
                    "dns_port": cfg.dns_port,
                    "ipv4_only": cfg.dns_ipv4_only,
                    "bind": cfg.addr.to_string(),
                    "port": cfg.port,
                    "socks_port": cfg.socks_port,
                    "timeout_ms": u64::try_from(cfg.connect_timeout.as_millis()).unwrap_or(u64::MAX),
                    "bypass_domains": cfg.bypass_domains,
                    "include_domains": cfg.patterns,
                    "split_tunnel_mode": cfg.split_tunnel.mode.as_str(),
                    "split_tunnel_apps": cfg.split_tunnel.apps,
                    "system_proxy": cfg.system_proxy,
                    "socks_system_proxy": cfg.socks_system_proxy,
                    "env_proxy": cfg.env_proxy,
                    "vpn_coexistence": cfg.vpn_coexistence.as_str(),
                    "tun_ipv6": cfg.tun_ipv6,
                });
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else {
                match loaded_path {
                    Some(path) => println!("# Config file: {}", path.display()),
                    None => println!(
                        "# Config file: {} (not created; using built-in defaults)",
                        resolve_config_path_for_display(explicit_path.as_deref(), service_mode)
                            .display()
                    ),
                }
                print!("{}", render_config_toml(&runtime_to_file_config(&cfg)));
            }
            Ok(())
        }
        ConfigCommand::Path => {
            let path = resolve_config_path_for_display(explicit_path.as_deref(), service_mode);
            println!("{}", path.display());
            Ok(())
        }
        ConfigCommand::Get { key } => {
            let (_, file_cfg) = load_file_config(explicit_path.as_deref(), service_mode)?;
            match get_config_key(&file_cfg, &key)? {
                Some(val) => println!("{val}"),
                None => {
                    let effective =
                        runtime_to_file_config(&cli.resolve_runtime_config(&file_cfg, raw_args));
                    if let Some(default_val) = get_config_key(&effective, &key)? {
                        println!("{default_val}");
                    }
                }
            }
            Ok(())
        }
        ConfigCommand::Set { key, value } => {
            let target = resolve_writable_config_path(explicit_path.as_deref(), service_mode)?;
            let (_, mut file_cfg) = load_file_config_or_default(Some(&target), service_mode)?;
            file_cfg.schema_version.get_or_insert(CONFIG_SCHEMA_VERSION);
            set_config_key(&mut file_cfg, &key, &value)?;
            if file_cfg.chunk_size == Some(0) {
                anyhow::bail!("chunk_size must be at least 1");
            }
            let resolved = cli.resolve_runtime_config(&file_cfg, raw_args);
            if resolved.chunk_size < 1 {
                anyhow::bail!("chunk_size must be at least 1");
            }
            let _ = BypassPolicy::new(&resolved.bypass_domains, &resolved.patterns)?;
            save_file_config_atomic(&target, &file_cfg)?;
            println!("Set {key} = {value} in {}", target.display());
            Ok(())
        }
        ConfigCommand::Unset { key } => {
            let target = resolve_writable_config_path(explicit_path.as_deref(), service_mode)?;
            let (loaded_path, mut file_cfg) =
                load_file_config_or_default(Some(&target), service_mode)?;
            unset_config_key(&mut file_cfg, &key)?;
            if loaded_path.is_none() {
                println!("No config file at {}; nothing to unset.", target.display());
                return Ok(());
            }
            save_file_config_atomic(&target, &file_cfg)?;
            println!("Unset {key} in {}", target.display());
            Ok(())
        }
        ConfigCommand::Validate => {
            let (loaded_path, file_cfg) = load_file_config(explicit_path.as_deref(), service_mode)?;
            if file_cfg.chunk_size == Some(0) {
                anyhow::bail!("chunk_size must be at least 1");
            }
            let cfg = cli.resolve_runtime_config(&file_cfg, raw_args);
            let _ = BypassPolicy::new(&cfg.bypass_domains, &cfg.patterns)?;
            match loaded_path {
                Some(path) => println!("Config valid: {}", path.display()),
                None => println!("No config.toml found (built-in defaults are valid)."),
            }
            Ok(())
        }
        ConfigCommand::Reset => {
            let target = resolve_writable_config_path(explicit_path.as_deref(), service_mode)?;
            let fresh = FileConfig {
                schema_version: Some(CONFIG_SCHEMA_VERSION),
                ..Default::default()
            };
            save_file_config_atomic(&target, &fresh)?;
            println!("Reset configuration to defaults: {}", target.display());
            Ok(())
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn parse_live_desync_mode(
    raw: Option<&str>,
    fallback: vdpi::config::DesyncMode,
) -> vdpi::config::DesyncMode {
    use vdpi::config::DesyncMode;
    let Some(value) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return fallback;
    };
    if value.eq_ignore_ascii_case("combo") {
        DesyncMode::Combo
    } else if value.eq_ignore_ascii_case("tls-record")
        || value.eq_ignore_ascii_case("tlsrec")
        || value.eq_ignore_ascii_case("tls_record")
    {
        DesyncMode::TlsRecord
    } else if value.eq_ignore_ascii_case("fragment") || value.eq_ignore_ascii_case("chunk") {
        DesyncMode::Fragment
    } else if value.eq_ignore_ascii_case("split") {
        DesyncMode::Split
    } else {
        fallback
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn dashboard_engine_from_live(
    live: &vdpi::service::LiveEngineStatus,
    system_proxy_fallback: bool,
) -> tui_dashboard::DashboardEngine {
    match live.engine {
        EngineMode::Tun => tui_dashboard::DashboardEngine::Tun {
            interface: live
                .tun_interface
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "vdpi0".to_string()),
            physical_nic: live.physical_nic.clone(),
            vpn_conflict: live.vpn_conflict.clone(),
        },
        EngineMode::Proxy => tui_dashboard::DashboardEngine::Proxy {
            primary_addr: std::net::SocketAddr::new(live.addr, live.port),
            socks_addr: live
                .socks_port
                .filter(|&p| p != 0)
                .map(|p| std::net::SocketAddr::new(live.addr, p)),
            system_proxy: system_proxy_fallback,
        },
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn telemetry_snapshot_from_live(
    live: &vdpi::service::LiveEngineStatus,
) -> vdpi::desync::EngineTelemetrySnapshot {
    vdpi::desync::EngineTelemetrySnapshot {
        active_connections: live.active_connections.unwrap_or(0),
        total_connections: live.total_connections.unwrap_or(0),
        bytes_tx: live.bytes_tx.unwrap_or(0),
        bytes_rx: live.bytes_rx.unwrap_or(0),
        tls_handshakes: live.tls_handshakes.unwrap_or(0),
        auto_heal_escalations: live.auto_heal_escalations.unwrap_or(0),
        learned_hosts: live.learned_hosts.unwrap_or(0),
        udp_flows_active: live.udp_flows_active.unwrap_or(0),
        quic_blocked: live.quic_blocked.unwrap_or(0),
        dns_queries: live.dns_queries.unwrap_or(0),
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn dashboard_info_from_live(
    live: &vdpi::service::LiveEngineStatus,
    fallback_cfg: &RuntimeConfig,
) -> tui_dashboard::DashboardInfo {
    tui_dashboard::DashboardInfo {
        engine: dashboard_engine_from_live(live, fallback_cfg.system_proxy),
        mode: parse_live_desync_mode(live.mode.as_deref(), fallback_cfg.mode),
        enable_doh: live.doh.unwrap_or(fallback_cfg.enable_doh),
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn attached_telemetry_from_live(
    live: &vdpi::service::LiveEngineStatus,
    fallback_cfg: &RuntimeConfig,
) -> tui_dashboard::AttachedTelemetry {
    tui_dashboard::AttachedTelemetry {
        snap: telemetry_snapshot_from_live(live),
        engine: dashboard_engine_from_live(live, fallback_cfg.system_proxy),
        mode: parse_live_desync_mode(live.mode.as_deref(), fallback_cfg.mode),
        doh: live.doh.unwrap_or(fallback_cfg.enable_doh),
        block_quic: live.block_quic.unwrap_or(fallback_cfg.block_quic),
        rss_kb: live.rss_kb,
        isp_stage: live.isp_stage.clone(),
        version: live.version.clone(),
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn probe_live_engine_for_dashboard(cfg: &RuntimeConfig) -> Option<vdpi::service::LiveEngineStatus> {
    vdpi::service::probe_control_center_status(cfg)
        .live_engine
        .or_else(|| {
            vdpi::service::probe_live_engine(cfg.addr, cfg.port, cfg.socks_port.unwrap_or(0))
        })
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn wait_for_attached_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, Signal, SignalKind};

        async fn wait_signal(sig: &mut Option<Signal>) {
            match sig.as_mut() {
                Some(s) => {
                    let _ = s.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        }

        let mut sigterm = signal(SignalKind::terminate()).ok();
        let mut sighup = signal(SignalKind::hangup()).ok();
        tokio::select! {
            _ = wait_signal(&mut sigterm) => {}
            _ = wait_signal(&mut sighup) => {}
        }
    }
    #[cfg(not(unix))]
    {
        // `run_attached_dashboard` handles q, Esc, and Ctrl-C key events directly in raw mode.
        std::future::pending::<()>().await;
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn run_attached_dashboard_for_live(
    live: &vdpi::service::LiveEngineStatus,
    cfg: &RuntimeConfig,
) -> Result<()> {
    let initial_info = dashboard_info_from_live(live, cfg);
    let initial_snap = telemetry_snapshot_from_live(live);
    let initial_rss_kb = live.rss_kb;
    let initial_isp_stage = live.isp_stage.clone();

    let live_addr = live.addr;
    let live_port = live.port;
    let live_socks_port = live.socks_port.unwrap_or(0);
    let probe_cfg = cfg.clone();

    let probe_fn = move || {
        let sampled = vdpi::service::probe_live_engine(live_addr, live_port, live_socks_port)
            .or_else(|| vdpi::service::probe_control_center_status(&probe_cfg).live_engine)?;
        Some(attached_telemetry_from_live(&sampled, &probe_cfg))
    };

    tui_dashboard::run_attached_dashboard(
        initial_info,
        initial_snap,
        initial_rss_kb,
        initial_isp_stage,
        probe_fn,
        wait_for_attached_shutdown(),
    )
    .await
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn run_attached_dashboard_for_status(
    status: &vdpi::service::ControlCenterStatus,
    cfg: &RuntimeConfig,
) -> Result<bool> {
    let Some(live) = status
        .live_engine
        .clone()
        .or_else(|| probe_live_engine_for_dashboard(cfg))
    else {
        return Ok(false);
    };
    run_attached_dashboard_for_live(&live, cfg).await?;
    Ok(true)
}

fn handle_dashboard_command(cfg: &RuntimeConfig) -> Result<()> {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = cfg;
        anyhow::bail!("live dashboard is not supported on {}", platform_name());
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let Some(live) = probe_live_engine_for_dashboard(cfg) else {
            println!("No running vdpi service detected. Run 'vdpi' or 'vdpi start' first.");
            return Ok(());
        };
        let rt = build_cli_runtime()?;
        rt.block_on(run_attached_dashboard_for_live(&live, cfg))
    }
}

fn merge_split_tunnel_apps(existing: &[String], to_add: &[String]) -> Result<Vec<String>> {
    let validated_add = vdpi::config_file::validate_split_tunnel_apps(to_add)?;
    if validated_add.is_empty() {
        anyhow::bail!("no valid application names provided");
    }
    let mut combined = Vec::with_capacity(existing.len().saturating_add(validated_add.len()));
    combined.extend(existing.iter().cloned());
    combined.extend(validated_add);
    vdpi::config_file::validate_split_tunnel_apps(&combined)
}

fn remove_split_tunnel_apps(existing: &[String], to_remove: &[String]) -> Vec<String> {
    let remove_keys: std::collections::HashSet<String> = to_remove
        .iter()
        .map(|raw| vdpi_core::config::normalize_split_app_name(raw))
        .filter(|key| !key.is_empty())
        .collect();
    existing
        .iter()
        .filter(|entry| !remove_keys.contains(&vdpi_core::config::normalize_split_app_name(entry)))
        .cloned()
        .collect()
}

fn handle_split_command(action: Option<SplitCommand>) -> Result<()> {
    match action {
        None => {
            #[cfg(any(target_os = "android", target_os = "ios"))]
            {
                anyhow::bail!(
                    "interactive split-tunnel picker is not supported on {}",
                    platform_name()
                );
            }
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                let current = vdpi::service::load_configured_split_tunnel();
                if let Some(new_cfg) = vdpi::split_tunnel::tui::run_split_tunnel_picker(current)? {
                    let msg = vdpi::service::set_service_split_tunnel(&new_cfg)?;
                    println!("{msg}");
                }
                Ok(())
            }
        }
        Some(SplitCommand::Status) => {
            let current = vdpi::service::load_configured_split_tunnel();
            println!("Split tunneling: {}", current.summary_label());
            println!("Mode: {}", current.mode.as_str());
            if current.apps.is_empty() {
                println!("Apps: (none)");
            } else {
                println!("Apps ({}):", current.apps.len());
                for app in &current.apps {
                    println!("  - {app}");
                }
            }
            Ok(())
        }
        Some(SplitCommand::List { query }) => {
            #[cfg(any(target_os = "android", target_os = "ios"))]
            {
                let _ = query;
                anyhow::bail!(
                    "application discovery is not supported on {}",
                    platform_name()
                );
            }
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                let current = vdpi::service::load_configured_split_tunnel();
                let discovered = vdpi::split_tunnel::discover_apps(&current.apps);
                let query_str = query.as_deref().unwrap_or("");
                let matched = vdpi::split_tunnel::filter_and_rank_apps(&discovered, query_str);
                if matched.is_empty() {
                    if query_str.trim().is_empty() {
                        println!("No applications discovered.");
                    } else {
                        println!("No applications matching '{}'.", query_str.trim());
                    }
                    return Ok(());
                }
                let selected_norm: std::collections::HashSet<String> = current
                    .apps
                    .iter()
                    .map(|a| vdpi::split_tunnel::normalize_exe(a))
                    .filter(|n| !n.is_empty())
                    .collect();
                for app in matched {
                    let checked =
                        selected_norm.contains(&vdpi::split_tunnel::normalize_exe(&app.exe_name));
                    let mark = if checked { "[x]" } else { "[ ]" };
                    let tag = if app.is_running {
                        "running"
                    } else {
                        match app.category {
                            vdpi::split_tunnel::AppCategory::Running => "running",
                            vdpi::split_tunnel::AppCategory::Popular => "popular",
                            vdpi::split_tunnel::AppCategory::Installed => "installed",
                            vdpi::split_tunnel::AppCategory::Custom => "custom",
                        }
                    };
                    println!(
                        "{mark} {:<28} {:<24} [{tag}]",
                        app.display_name, app.exe_name
                    );
                }
                Ok(())
            }
        }
        Some(SplitCommand::Mode { mode }) => {
            let mut current = vdpi::service::load_configured_split_tunnel();
            current.mode = mode;
            let msg = vdpi::service::set_service_split_tunnel(&current)?;
            println!("{msg}");
            Ok(())
        }
        Some(SplitCommand::Add { apps }) => {
            let mut current = vdpi::service::load_configured_split_tunnel();
            current.apps = merge_split_tunnel_apps(&current.apps, &apps)?;
            let msg = vdpi::service::set_service_split_tunnel(&current)?;
            println!("{msg}");
            if current.mode == SplitTunnelMode::All {
                println!(
                    "Note: split tunneling mode is currently 'all'. Run 'vdpi split mode exclude' or 'vdpi split mode include' to activate."
                );
            }
            Ok(())
        }
        Some(SplitCommand::Remove { apps }) => {
            let mut current = vdpi::service::load_configured_split_tunnel();
            current.apps = remove_split_tunnel_apps(&current.apps, &apps);
            let msg = vdpi::service::set_service_split_tunnel(&current)?;
            println!("{msg}");
            Ok(())
        }
        Some(SplitCommand::Clear) => {
            let cleared = SplitTunnelConfig::default();
            let msg = vdpi::service::set_service_split_tunnel(&cleared)?;
            println!("{msg}");
            Ok(())
        }
    }
}

fn format_live_engine_line(live: &vdpi::service::LiveEngineStatus) -> String {
    match live.engine {
        EngineMode::Tun => {
            let iface = live.tun_interface.as_deref();
            if matches!(iface, None | Some("standby")) {
                if let Some(vpn) = live.vpn_conflict.as_deref() {
                    if vpn.to_ascii_lowercase().contains("yielded") {
                        format!("Engine: tun (yielded, {vpn})")
                    } else {
                        format!("Engine: tun (standby, {vpn})")
                    }
                } else {
                    "Engine: tun (standby)".to_string()
                }
            } else {
                let iface = iface.unwrap_or("vdpi0");
                if let Some(nic) = live.physical_nic.as_deref() {
                    format!("Engine: tun (active, {iface} via {nic})")
                } else {
                    format!("Engine: tun (active, {iface})")
                }
            }
        }
        EngineMode::Proxy => {
            format!(
                "Engine: proxy (active, {})",
                std::net::SocketAddr::new(live.addr, live.port)
            )
        }
    }
}

fn build_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(Into::into)
}

fn build_cli_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(Into::into)
}

fn get_or_init_cli_runtime(
    slot: &mut Option<tokio::runtime::Runtime>,
) -> Result<&tokio::runtime::Runtime> {
    if slot.is_none() {
        *slot = Some(build_cli_runtime()?);
    }
    match slot.as_ref() {
        Some(rt) => Ok(rt),
        None => unreachable!("cli runtime was just initialized"),
    }
}

fn wait_for_live_engine(cfg: &RuntimeConfig, target: EngineMode) {
    let wait_ms = match target {
        EngineMode::Tun => 2500,
        EngineMode::Proxy => 1200,
    };
    let deadline = Instant::now() + Duration::from_millis(wait_ms);
    loop {
        if vdpi::service::probe_control_center_status(cfg)
            .live_engine
            .is_some_and(|live| live.engine == target)
        {
            return;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        std::thread::sleep(remaining.min(Duration::from_millis(150)));
    }
}

#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
fn normalize_system_proxy_addr(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    let ip = match addr.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    };
    SocketAddr::new(ip, addr.port())
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[derive(Clone)]
struct ForegroundProxySpec {
    proxy_addr: std::net::SocketAddr,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    socks_port: Option<u16>,
    #[cfg(windows)]
    env_proxy: bool,
    bypass_domains: Vec<String>,
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
impl ForegroundProxySpec {
    fn activate(&self) -> Result<(foreground::ForegroundProxy, String)> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let session = foreground::ForegroundProxy::activate(
                self.proxy_addr,
                self.socks_port,
                &self.bypass_domains,
            )?;
            let summary = session.summary.clone();
            Ok((session, summary))
        }
        #[cfg(windows)]
        {
            let session = foreground::ForegroundProxy::activate(
                self.proxy_addr,
                self.env_proxy,
                &self.bypass_domains,
            )?;
            let summary = if self.env_proxy {
                "active (WinINET + HTTP_PROXY/HTTPS_PROXY with auto-cleanup)".to_string()
            } else {
                "active (WinINET proxy with auto-cleanup)".to_string()
            };
            Ok((session, summary))
        }
    }
}

fn sanitize_notice(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_space = false;
    for ch in input.chars() {
        if matches!(ch, '\n' | '\r' | '\t' | ' ') {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else if !ch.is_control() {
            out.push(ch);
            prev_space = false;
        }
    }
    out.trim().to_string()
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct DashboardTracing {
    logs: tui_dashboard::SharedLogRing,
    passthrough_stderr: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

async fn run_daemon(
    cfg: RuntimeConfig,
    #[cfg(not(any(target_os = "android", target_os = "ios")))] dashboard_tracing: Option<
        DashboardTracing,
    >,
) -> Result<()> {
    if cfg.engine == EngineMode::Tun {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            return desktop_tun::run_tun_daemon(cfg, dashboard_tracing).await;
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            anyhow::bail!(
                "desktop TUN mode is not supported on {} CLI; use --proxy instead",
                platform_name()
            );
        }
    }

    let ctx = EngineContext::new(cfg.clone())?;
    if let Some(cache_path) = vdpi::desync::default_desktop_cache_path() {
        ctx.attach_cache_file(cache_path).await;
    }
    let bound = bind_listeners(&ctx)?;

    let primary_addr = bound.primary_addr;
    let socks_addr = bound.socks_addr;

    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    let (proxy_spec, mut proxy_session, proxy_summary, mut proxy_vpn_guard, mut proxy_last_warned) = {
        use vdpi::config::VpnCoexistence;
        use vdpi::platform::vpn::{detect_active_vpn, VpnScope};
        use vdpi::platform::vpn_guard::{GuardAction, VpnGuard};

        let mut vpn_guard = VpnGuard::new(cfg.vpn_coexistence);
        let mut last_warned: Option<String> = None;

        if cfg.system_proxy {
            let spec = ForegroundProxySpec {
                proxy_addr: normalize_system_proxy_addr(primary_addr),
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                socks_port: socks_addr
                    .filter(|_| cfg.socks_system_proxy)
                    .map(|a| a.port()),
                #[cfg(windows)]
                env_proxy: cfg.env_proxy,
                bypass_domains: cfg.bypass_domains.clone(),
            };

            let initial_scope = if cfg.vpn_coexistence != VpnCoexistence::Off {
                tokio::task::spawn_blocking(|| detect_active_vpn(None))
                    .await
                    .unwrap_or(VpnScope::None)
            } else {
                VpnScope::None
            };
            let initial_action = vpn_guard.evaluate(&initial_scope, Instant::now());

            match initial_action {
                GuardAction::YieldTun { provider } => {
                    warn!(
                        provider = %provider,
                        "full-tunnel VPN active at startup; holding system proxy in yielded standby until VPN disconnects"
                    );
                    (
                        Some(spec),
                        None,
                        Some(format!("standby (yielded to {provider})")),
                        vpn_guard,
                        last_warned,
                    )
                }
                GuardAction::WarnOnly { provider } => {
                    warn!(
                        provider = %provider,
                        "full-tunnel VPN detected (vpn_coexistence=warn); activating system proxy anyway"
                    );
                    last_warned = Some(provider);
                    let act_spec = spec.clone();
                    let (session, summary) =
                        tokio::task::spawn_blocking(move || act_spec.activate())
                            .await
                            .map_err(|e| {
                                anyhow::anyhow!("system proxy activation task panicked: {e}")
                            })??;
                    (
                        Some(spec),
                        Some(session),
                        Some(summary),
                        vpn_guard,
                        last_warned,
                    )
                }
                GuardAction::None | GuardAction::ResumeTun => {
                    let act_spec = spec.clone();
                    let (session, summary) =
                        tokio::task::spawn_blocking(move || act_spec.activate())
                            .await
                            .map_err(|e| {
                                anyhow::anyhow!("system proxy activation task panicked: {e}")
                            })??;
                    (
                        Some(spec),
                        Some(session),
                        Some(summary),
                        vpn_guard,
                        last_warned,
                    )
                }
            }
        } else {
            (None, None, None, vpn_guard, last_warned)
        }
    };
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    let proxy_summary: Option<String> = None;

    write_runtime_state(primary_addr, socks_addr);

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let use_dashboard = dashboard_tracing.is_some();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let use_dashboard = false;

    if !cfg.quiet {
        if !use_dashboard {
            print_startup_banner(&cfg, primary_addr, socks_addr, proxy_summary.as_deref());
        }
        info!(
            platform = platform_name(),
            mode = ?cfg.mode,
            chunk_size = cfg.chunk_size,
            doh = cfg.enable_doh,
            system_proxy = cfg.system_proxy,
            vpn_coexistence = cfg.vpn_coexistence.as_str(),
            "vdpi engine active"
        );
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    let proxy_supervisor_task = proxy_spec.map(|spec| {
        use vdpi::config::VpnCoexistence;
        use vdpi::platform::vpn::{detect_active_vpn, VpnScope};
        use vdpi::platform::vpn_guard::GuardAction;

        let mut sup_shutdown_rx = shutdown_rx.clone();
        let vpn_policy = cfg.vpn_coexistence;
        tokio::spawn(async move {
            if vpn_policy == VpnCoexistence::Off {
                let _ = sup_shutdown_rx.wait_for(|stopped| *stopped).await;
            } else {
                let mut vpn_tick = tokio::time::interval(Duration::from_secs(1));
                vpn_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                vpn_tick.tick().await;

                let mut last_resume_attempt: Option<Instant> = None;
                let mut last_activate_error: Option<(String, Instant)> = None;

                loop {
                    tokio::select! {
                        biased;
                        changed = sup_shutdown_rx.changed() => {
                            if changed.is_err() || *sup_shutdown_rx.borrow() {
                                break;
                            }
                        }
                        _ = vpn_tick.tick() => {
                            let scope = tokio::task::spawn_blocking(|| detect_active_vpn(None))
                                .await
                                .unwrap_or(VpnScope::None);
                            if *sup_shutdown_rx.borrow() {
                                break;
                            }
                            let now = Instant::now();
                            let action = proxy_vpn_guard.evaluate(&scope, now);

                            match action {
                                GuardAction::YieldTun { provider } => {
                                    proxy_last_warned = None;
                                    last_activate_error = None;
                                    if let Some(session) = proxy_session.take() {
                                        warn!(
                                            provider = %provider,
                                            "full-tunnel VPN active; yielding system proxy cleanly"
                                        );
                                        let _ = tokio::task::spawn_blocking(move || drop(session))
                                            .await;
                                    }
                                }
                                GuardAction::ResumeTun => {
                                    proxy_last_warned = None;
                                    if proxy_session.is_none() {
                                        let cooldown_ok = last_resume_attempt.is_none_or(|t| {
                                            now.saturating_duration_since(t)
                                                >= Duration::from_secs(3)
                                        });
                                        if cooldown_ok {
                                            if *sup_shutdown_rx.borrow() {
                                                break;
                                            }
                                            last_resume_attempt = Some(now);
                                            let act_spec = spec.clone();
                                            let res = match tokio::task::spawn_blocking(move || {
                                                act_spec.activate()
                                            })
                                            .await
                                            {
                                                Ok(inner) => inner,
                                                Err(e) => Err(anyhow::anyhow!(
                                                    "system proxy activation task panicked: {e}"
                                                )),
                                            };
                                            match res {
                                                Ok((session, _)) => {
                                                    if *sup_shutdown_rx.borrow() {
                                                        let _ = tokio::task::spawn_blocking(
                                                            move || drop(session),
                                                        )
                                                        .await;
                                                        break;
                                                    }
                                                    proxy_session = Some(session);
                                                    last_activate_error = None;
                                                    info!(
                                                        "full-tunnel VPN cleared; resumed system proxy"
                                                    );
                                                }
                                                Err(err) => {
                                                    let msg = format!("{err:#}");
                                                    let should_log = last_activate_error
                                                        .as_ref()
                                                        .is_none_or(|(prev, ts)| {
                                                            prev != &msg
                                                                || now.saturating_duration_since(*ts)
                                                                    >= Duration::from_secs(30)
                                                        });
                                                    if should_log {
                                                        warn!(
                                                            error = %err,
                                                            "failed to resume system proxy after VPN disconnect; will retry"
                                                        );
                                                        last_activate_error = Some((msg, now));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                GuardAction::WarnOnly { provider } => {
                                    if proxy_last_warned.as_deref() != Some(provider.as_str()) {
                                        warn!(
                                            provider = %provider,
                                            "full-tunnel VPN detected while vpn_coexistence=warn"
                                        );
                                        proxy_last_warned = Some(provider);
                                    }
                                }
                                GuardAction::None => {
                                    if !scope.is_full_tunnel() {
                                        proxy_last_warned = None;
                                    }
                                    if !proxy_vpn_guard.is_yielded() && proxy_session.is_none() {
                                        let cooldown_ok = last_resume_attempt.is_none_or(|t| {
                                            now.saturating_duration_since(t)
                                                >= Duration::from_secs(3)
                                        });
                                        if cooldown_ok {
                                            if *sup_shutdown_rx.borrow() {
                                                break;
                                            }
                                            last_resume_attempt = Some(now);
                                            let act_spec = spec.clone();
                                            let res = match tokio::task::spawn_blocking(move || {
                                                act_spec.activate()
                                            })
                                            .await
                                            {
                                                Ok(inner) => inner,
                                                Err(e) => Err(anyhow::anyhow!(
                                                    "system proxy activation task panicked: {e}"
                                                )),
                                            };
                                            match res {
                                                Ok((session, _)) => {
                                                    if *sup_shutdown_rx.borrow() {
                                                        let _ = tokio::task::spawn_blocking(
                                                            move || drop(session),
                                                        )
                                                        .await;
                                                        break;
                                                    }
                                                    proxy_session = Some(session);
                                                    last_activate_error = None;
                                                    info!("resumed system proxy after retry");
                                                }
                                                Err(err) => {
                                                    let msg = format!("{err:#}");
                                                    let should_log = last_activate_error
                                                        .as_ref()
                                                        .is_none_or(|(prev, ts)| {
                                                            prev != &msg
                                                                || now.saturating_duration_since(*ts)
                                                                    >= Duration::from_secs(30)
                                                        });
                                                    if should_log {
                                                        warn!(
                                                            error = %err,
                                                            "failed to re-activate system proxy; will retry"
                                                        );
                                                        last_activate_error = Some((msg, now));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if let Some(session) = proxy_session.take() {
                let _ = tokio::task::spawn_blocking(move || drop(session)).await;
            }
        })
    });

    let server_task = tokio::spawn(serve_until_shutdown(bound, ctx.clone(), shutdown_rx));

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if let Some(dashboard) = dashboard_tracing {
        let dash_info = tui_dashboard::DashboardInfo {
            engine: tui_dashboard::DashboardEngine::Proxy {
                primary_addr,
                socks_addr,
                system_proxy: cfg.system_proxy,
            },
            mode: cfg.mode,
            enable_doh: cfg.enable_doh,
        };

        if let Err(err) = tui_dashboard::run_dashboard(
            dash_info,
            ctx.clone(),
            dashboard.logs,
            shutdown_tx.clone(),
            wait_for_shutdown_signal(),
        )
        .await
        {
            dashboard
                .passthrough_stderr
                .store(true, std::sync::atomic::Ordering::Relaxed);
            eprintln!("vdpi dashboard unavailable ({err}); running in headless mode");
            if !cfg.quiet {
                print_startup_banner(&cfg, primary_addr, socks_addr, proxy_summary.as_deref());
            }
            wait_for_shutdown_signal().await;
        }
    } else {
        wait_for_shutdown_signal().await;
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    wait_for_shutdown_signal().await;

    info!("received shutdown signal; stopping vdpi cleanly");
    let _ = shutdown_tx.send(true);
    clear_runtime_state(std::process::id());

    let server_wait = tokio::time::timeout(Duration::from_secs(2), server_task);
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    {
        let proxy_wait = async {
            if let Some(task) = proxy_supervisor_task {
                let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
            }
        };
        let (_, _) = tokio::join!(proxy_wait, server_wait);
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = server_wait.await;
    }
    if let Err(err) = ctx.flush_persisted_cache().await {
        debug!(error = %err, "failed to flush adaptive cache on shutdown");
    }
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod desktop_tun {
    use super::{wait_for_shutdown_signal, DashboardTracing};
    use crate::tui_dashboard::{self, DashboardEngine, DashboardInfo, TunLiveMeta, TunMetaProbe};
    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    use anyhow::Context;
    use anyhow::Result;
    use std::net::SocketAddr;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::sync::watch;
    use tracing::{debug, error, info, warn};
    use vdpi::binder::{DynamicOutboundBinder, OutboundBinder, OutboundTarget};
    use vdpi::config::{EngineMode, RuntimeConfig, VpnCoexistence};
    use vdpi::desync::EngineContext;
    use vdpi::health::{
        bind_loopback_health_listener, serve_health_until_shutdown, HealthMetaFn,
        HealthRuntimeMeta, DEFAULT_TUN_HEALTH_PORT,
    };
    use vdpi::platform::platform_name;
    use vdpi::platform::vpn::{detect_active_vpn, VpnScope};
    use vdpi::platform::vpn_guard::{GuardAction, VpnGuard};
    use vdpi::service::{clear_runtime_state, write_runtime_state_with_meta};
    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    use vdpi_tun::config::TunProfile;
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    use vdpi_tun::config::DESKTOP_MTU;
    use vdpi_tun::events::EventRing;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    use vdpi_tun::fd::register_tun_fd;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    use vdpi_tun::fd::run_registered_tun_fd_with_app_bypass;
    #[cfg(target_os = "windows")]
    use vdpi_tun::pipeline::run_tun_pipeline_with_app_bypass;
    use vdpi_tun::pipeline::TunStats;

    const MAX_CONSECUTIVE_PIPELINE_EXITS: u32 = 5;
    const HEALTHY_PIPELINE_UPTIME: Duration = Duration::from_secs(30);

    pub(super) fn retry_backoff(failures: u32) -> Duration {
        let shift = failures.saturating_sub(1).min(4);
        let secs = 3u64.saturating_mul(1u64 << shift).min(30);
        Duration::from_secs(secs)
    }

    fn is_fatal_tun_start_error(err: &anyhow::Error) -> bool {
        let lower = format!("{err:#}").to_ascii_lowercase();
        lower.contains("access is denied")
            || lower.contains("error 5")
            || lower.contains("permission denied")
            || lower.contains("operation not permitted")
            || lower.contains("requires root privileges")
            || lower.contains("not supported on")
            || (lower.contains("wintun.dll")
                && (lower.contains("not found")
                    || lower.contains("missing")
                    || lower.contains("sha-256")
                    || lower.contains("verify")
                    || lower.contains("loadlibrary")))
    }

    enum PlatformTunHandle {
        #[cfg(target_os = "windows")]
        Windows(vdpi::platform::windows_tun::WindowsTunSession),
        #[cfg(target_os = "macos")]
        Macos(vdpi::platform::macos_tun::MacosTunSession),
        #[cfg(target_os = "linux")]
        Linux(vdpi::platform::linux_tun::LinuxTunSession),
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        Unsupported,
    }

    impl PlatformTunHandle {
        fn iface_name(&self) -> String {
            match self {
                #[cfg(target_os = "windows")]
                Self::Windows(s) => s.iface_name().to_string(),
                #[cfg(target_os = "macos")]
                Self::Macos(s) => s.iface_name().to_string(),
                #[cfg(target_os = "linux")]
                Self::Linux(s) => s.iface_name().to_string(),
                #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
                Self::Unsupported => "vdpi0".to_string(),
            }
        }

        fn physical_nic_name(&self) -> Option<String> {
            match self {
                #[cfg(target_os = "windows")]
                Self::Windows(s) => s.physical_nic_name(),
                #[cfg(target_os = "macos")]
                Self::Macos(s) => Some(s.physical_nic_name().to_string()),
                #[cfg(target_os = "linux")]
                Self::Linux(_) => None,
                #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
                Self::Unsupported => None,
            }
        }
    }

    struct DesktopTunSlot {
        session: Option<PlatformTunHandle>,
        pipeline_stop_tx: Option<watch::Sender<bool>>,
        pipeline_task: Option<tokio::task::JoinHandle<Result<()>>>,
        #[cfg(any(target_os = "windows", target_os = "macos"))]
        route_rx: Option<watch::Receiver<u64>>,
    }

    impl DesktopTunSlot {
        fn empty() -> Self {
            Self {
                session: None,
                pipeline_stop_tx: None,
                pipeline_task: None,
                #[cfg(any(target_os = "windows", target_os = "macos"))]
                route_rx: None,
            }
        }

        fn is_running(&self) -> bool {
            self.session.is_some()
        }

        fn iface_name(&self) -> Option<String> {
            self.session.as_ref().map(PlatformTunHandle::iface_name)
        }

        fn physical_nic_name(&self) -> Option<String> {
            self.session
                .as_ref()
                .and_then(PlatformTunHandle::physical_nic_name)
        }

        async fn start(
            &mut self,
            binder: &Arc<DynamicOutboundBinder>,
            tun_ipv6: bool,
            ctx: &EngineContext,
            tun_stats: &Arc<TunStats>,
            events: &Arc<EventRing>,
        ) -> Result<()> {
            if self.session.is_some() {
                return Ok(());
            }

            #[cfg(target_os = "windows")]
            {
                use vdpi::platform::windows_tun::WindowsTunSession;

                let start_binder = Arc::clone(binder);
                let (session, inbound_rx, outbound_tx, route_rx) =
                    tokio::task::spawn_blocking(move || {
                        WindowsTunSession::start(start_binder, tun_ipv6)
                    })
                    .await
                    .context("Windows TUN startup task panicked")?
                    .map_err(format_tun_start_error)?;

                let app_bypass =
                    vdpi::split_tunnel::build_tun_app_bypass_hook(&ctx.config.split_tunnel);
                let (stop_tx, stop_rx) = watch::channel(false);
                let pipeline_task = tokio::spawn(run_tun_pipeline_with_app_bypass(
                    inbound_rx,
                    outbound_tx,
                    ctx.clone(),
                    Arc::clone(tun_stats),
                    Arc::clone(events),
                    DESKTOP_MTU,
                    TunProfile::DESKTOP,
                    stop_rx,
                    Some(route_rx.clone()),
                    app_bypass,
                ));

                self.session = Some(PlatformTunHandle::Windows(session));
                self.pipeline_stop_tx = Some(stop_tx);
                self.pipeline_task = Some(pipeline_task);
                self.route_rx = Some(route_rx);
                Ok(())
            }

            #[cfg(target_os = "macos")]
            {
                use vdpi::platform::macos_tun::MacosTunSession;

                let start_binder = Arc::clone(binder);
                let (session, tun_fd) = tokio::task::spawn_blocking(move || {
                    MacosTunSession::start(start_binder, tun_ipv6)
                })
                .await
                .context("macOS TUN startup task panicked")?
                .map_err(format_tun_start_error)?;

                let async_fd = match register_tun_fd(tun_fd) {
                    Ok(fd) => fd,
                    Err(err) => {
                        let _ = tokio::task::spawn_blocking(move || drop(session)).await;
                        return Err(format_tun_start_error(err));
                    }
                };

                let tun_mtu = usize::from(session.mtu());
                let route_rx = session.route_change_rx();
                let app_bypass =
                    vdpi::split_tunnel::build_tun_app_bypass_hook(&ctx.config.split_tunnel);
                let (stop_tx, stop_rx) = watch::channel(false);
                let pipeline_task = tokio::spawn(run_registered_tun_fd_with_app_bypass(
                    async_fd,
                    ctx.clone(),
                    Arc::clone(tun_stats),
                    Arc::clone(events),
                    tun_mtu,
                    TunProfile::DESKTOP,
                    stop_rx,
                    Some(route_rx.clone()),
                    app_bypass,
                ));

                self.session = Some(PlatformTunHandle::Macos(session));
                self.pipeline_stop_tx = Some(stop_tx);
                self.pipeline_task = Some(pipeline_task);
                self.route_rx = Some(route_rx);
                Ok(())
            }

            #[cfg(target_os = "linux")]
            {
                use vdpi::platform::linux_tun::LinuxTunSession;

                let start_binder = Arc::clone(binder);
                let (session, tun_fd) = tokio::task::spawn_blocking(move || {
                    LinuxTunSession::start(start_binder, tun_ipv6)
                })
                .await
                .context("Linux TUN startup task panicked")?
                .map_err(format_tun_start_error)?;

                let async_fd = match register_tun_fd(tun_fd) {
                    Ok(fd) => fd,
                    Err(err) => {
                        let _ = tokio::task::spawn_blocking(move || drop(session)).await;
                        return Err(format_tun_start_error(err));
                    }
                };

                let app_bypass =
                    vdpi::split_tunnel::build_tun_app_bypass_hook(&ctx.config.split_tunnel);
                let (stop_tx, stop_rx) = watch::channel(false);
                let pipeline_task = tokio::spawn(run_registered_tun_fd_with_app_bypass(
                    async_fd,
                    ctx.clone(),
                    Arc::clone(tun_stats),
                    Arc::clone(events),
                    DESKTOP_MTU,
                    TunProfile::DESKTOP,
                    stop_rx,
                    None,
                    app_bypass,
                ));

                self.session = Some(PlatformTunHandle::Linux(session));
                self.pipeline_stop_tx = Some(stop_tx);
                self.pipeline_task = Some(pipeline_task);
                Ok(())
            }

            #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
            {
                let _ = (binder, tun_ipv6, ctx, tun_stats, events);
                Err(format_tun_start_error(anyhow::anyhow!(
                    "desktop TUN mode is not supported on {}",
                    platform_name()
                )))
            }
        }

        async fn stop(&mut self) {
            #[cfg(any(target_os = "windows", target_os = "macos"))]
            {
                self.route_rx = None;
            }
            if let Some(tx) = self.pipeline_stop_tx.take() {
                let _ = tx.send(true);
            }
            if let Some(mut task) = self.pipeline_task.take() {
                if tokio::time::timeout(Duration::from_secs(2), &mut task)
                    .await
                    .is_err()
                {
                    task.abort();
                    let _ = tokio::time::timeout(Duration::from_millis(500), &mut task).await;
                }
            }
            if let Some(session) = self.session.take() {
                let _ = tokio::task::spawn_blocking(move || drop(session)).await;
            }
        }
    }

    pub(super) fn format_tun_start_error(err: anyhow::Error) -> anyhow::Error {
        let chain = format!("{err:#}");
        #[cfg(target_os = "windows")]
        {
            let lower = chain.to_ascii_lowercase();
            if lower.contains("wintun.dll")
                || (lower.contains("wintun")
                    && (lower.contains("not found")
                        || lower.contains("missing")
                        || lower.contains("sha-256")
                        || lower.contains("verify")
                        || lower.contains("loadlibrary")))
            {
                return anyhow::anyhow!(
                    "failed to start Windows TUN mode: {chain}\n\n\
                     To fix this:\n  \
                     - Ensure the official WHQL-signed wintun.dll is next to vdpi.exe (re-download the release archive or run `vdpi update --force`).\n  \
                     - Or switch to Proxy mode without a virtual adapter: `vdpi --proxy start` (or `vdpi engine proxy`)."
                );
            }
            if lower.contains("access is denied")
                || lower.contains("error 5")
                || lower.contains("administrator")
                || lower.contains("privilege")
                || lower.contains("wintuncreateadapter")
            {
                return anyhow::anyhow!(
                    "failed to start Windows TUN mode: {chain}\n\n\
                     To fix this:\n  \
                     - Re-run from an elevated Administrator terminal (`vdpi --tun start`) or install the background service (`vdpi install --tun`).\n  \
                     - Or switch to unprivileged Proxy mode: `vdpi --proxy start` (or `vdpi engine proxy`)."
                );
            }
            anyhow::anyhow!(
                "failed to start Windows TUN mode: {chain}\n\n\
                 Tip: Run elevated as Administrator with wintun.dll next to vdpi.exe, or switch to Proxy mode with `vdpi --proxy start` (`vdpi engine proxy`)."
            )
        }
        #[cfg(target_os = "macos")]
        {
            anyhow::anyhow!(
                "failed to start macOS TUN mode: {chain}\n\n\
                 To fix this:\n  \
                 - Run with root privileges (`sudo vdpi --tun start`) or install the system LaunchDaemon (`sudo vdpi install --tun`).\n  \
                 - Or switch to unprivileged Proxy mode: `vdpi --proxy start` (or `vdpi engine proxy`)."
            )
        }
        #[cfg(target_os = "linux")]
        {
            anyhow::anyhow!(
                "failed to start Linux TUN mode: {chain}\n\n\
                 To fix this:\n  \
                 - Run elevated (`sudo vdpi --tun start`), grant CAP_NET_ADMIN (`sudo setcap cap_net_admin+eip $(which vdpi)`), or install the system service (`sudo vdpi install --tun`).\n  \
                 - Or switch to unprivileged Proxy mode: `vdpi --proxy start` (or `vdpi engine proxy`)."
            )
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            anyhow::anyhow!(
                "failed to start TUN mode: {chain}\n\n\
                 Tip: Switch to Proxy mode with `vdpi --proxy start`."
            )
        }
    }

    fn sync_tun_telemetry(ctx: &EngineContext, tun_stats: &TunStats) {
        ctx.set_udp_flows_active(tun_stats.udp_flows_active.load(Ordering::Relaxed));
        let quic = tun_stats.quic_blocked.load(Ordering::Relaxed);
        ctx.telemetry
            .quic_blocked
            .fetch_max(quic, Ordering::Relaxed);
    }

    async fn wait_pipeline_exit(
        task: &mut Option<tokio::task::JoinHandle<Result<()>>>,
    ) -> Result<()> {
        match task.as_mut() {
            Some(handle) => {
                let res = handle.await;
                *task = None;
                match res {
                    Ok(inner) => inner,
                    Err(err) => Err(anyhow::anyhow!("TUN pipeline task panicked: {err}")),
                }
            }
            None => std::future::pending().await,
        }
    }

    #[cfg(any(target_os = "windows", target_os = "macos"))]
    async fn wait_route_change(route_rx: &mut Option<watch::Receiver<u64>>) {
        match route_rx.as_mut() {
            Some(rx) => {
                if rx.changed().await.is_err() {
                    *route_rx = None;
                    std::future::pending::<()>().await;
                }
            }
            None => std::future::pending::<()>().await,
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    async fn wait_route_change() {
        std::future::pending::<()>().await;
    }

    struct TunStartEnv {
        binder: Arc<DynamicOutboundBinder>,
        ctx: EngineContext,
        tun_stats: Arc<TunStats>,
        events: Arc<EventRing>,
        tun_ipv6: bool,
        health_addr: SocketAddr,
    }

    struct TunRetryState {
        last_attempt: Option<Instant>,
        next_retry_at: Option<Instant>,
        consecutive_failures: u32,
        consecutive_pipeline_exits: u32,
        last_started_at: Option<Instant>,
        last_start_error: Option<(String, Instant)>,
    }

    impl TunRetryState {
        fn new(running: bool) -> Self {
            Self {
                last_attempt: None,
                next_retry_at: None,
                consecutive_failures: 0,
                consecutive_pipeline_exits: 0,
                last_started_at: running.then(Instant::now),
                last_start_error: None,
            }
        }

        fn retry_due(&self, now: Instant) -> bool {
            let cooldown_ok = self
                .last_attempt
                .is_none_or(|t| now.saturating_duration_since(t) >= Duration::from_secs(3));
            let backoff_ok = self.next_retry_at.is_none_or(|at| now >= at);
            cooldown_ok && backoff_ok
        }

        fn record_started(&mut self, now: Instant) {
            self.consecutive_failures = 0;
            self.next_retry_at = None;
            self.last_start_error = None;
            self.last_started_at = Some(now);
        }

        fn record_yielded(&mut self) {
            self.consecutive_failures = 0;
            self.consecutive_pipeline_exits = 0;
            self.next_retry_at = None;
            self.last_start_error = None;
            self.last_started_at = None;
        }

        fn record_start_failure(&mut self, now: Instant, err: &anyhow::Error) {
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            let backoff = retry_backoff(self.consecutive_failures);
            self.next_retry_at = Some(now + backoff);
            let err_text = format!("{err:#}");
            let should_log = self.last_start_error.as_ref().is_none_or(|(prev, ts)| {
                prev != &err_text || now.saturating_duration_since(*ts) >= Duration::from_secs(30)
            });
            if should_log {
                warn!(
                    error = %err,
                    retry_in_secs = backoff.as_secs(),
                    "failed to start or resume TUN session; will retry"
                );
                self.last_start_error = Some((err_text, now));
            }
        }
    }

    enum LoopEvent {
        None,
        Reconcile,
        PipelineExited,
        RetryStart,
    }

    enum StartOutcome {
        Started,
        Shutdown,
        RetryLater,
        Fatal(anyhow::Error),
    }

    async fn try_start_slot(
        slot: &mut DesktopTunSlot,
        env: &TunStartEnv,
        shutdown_rx: &watch::Receiver<bool>,
        retry: &mut TunRetryState,
        now: Instant,
        success_msg: &str,
    ) -> StartOutcome {
        if *shutdown_rx.borrow() {
            return StartOutcome::Shutdown;
        }
        retry.last_attempt = Some(now);
        let start_res = slot
            .start(
                &env.binder,
                env.tun_ipv6,
                &env.ctx,
                &env.tun_stats,
                &env.events,
            )
            .await;
        if *shutdown_rx.borrow() {
            slot.stop().await;
            return StartOutcome::Shutdown;
        }
        match start_res {
            Ok(()) => {
                retry.record_started(Instant::now());
                let iface = slot.iface_name().unwrap_or_else(|| "vdpi0".to_string());
                write_runtime_state_with_meta(
                    env.health_addr,
                    None,
                    EngineMode::Tun,
                    Some(iface.clone()),
                    None,
                );
                info!(iface = %iface, "{success_msg}");
                StartOutcome::Started
            }
            Err(err) => {
                if is_fatal_tun_start_error(&err) {
                    error!(error = %err, "unrecoverable TUN startup error");
                    return StartOutcome::Fatal(err);
                }
                retry.record_start_failure(now, &err);
                StartOutcome::RetryLater
            }
        }
    }

    fn update_health_meta(
        health_meta: &Arc<Mutex<HealthRuntimeMeta>>,
        binder: &Arc<DynamicOutboundBinder>,
        slot: &DesktopTunSlot,
        guard: &VpnGuard,
        scope: &VpnScope,
    ) {
        let mut meta = health_meta.lock().unwrap_or_else(|e| e.into_inner());
        meta.engine = EngineMode::Tun;
        meta.tun_interface = slot.iface_name().or_else(|| Some("standby".to_string()));
        meta.physical_nic = if slot.is_running() {
            binder
                .physical_nic_name()
                .or_else(|| slot.physical_nic_name())
        } else {
            None
        };
        meta.vpn_conflict = guard.active_conflict_label(scope);
    }

    pub(super) async fn run_tun_daemon(
        cfg: RuntimeConfig,
        dashboard_tracing: Option<DashboardTracing>,
    ) -> Result<()> {
        let binder = DynamicOutboundBinder::new(OutboundTarget::default());
        let binder_dyn: Arc<dyn OutboundBinder> = binder.clone();
        let ctx = EngineContext::new_with_binder(cfg.clone(), Some(binder_dyn))?;
        if let Some(cache_path) = vdpi::desync::default_desktop_cache_path() {
            ctx.attach_cache_file(cache_path).await;
        }

        let tun_stats = Arc::new(TunStats::default());
        let events = Arc::new(EventRing::new());
        let mut vpn_guard = VpnGuard::new(cfg.vpn_coexistence);
        let mut slot = DesktopTunSlot::empty();

        let initial_scope = tokio::task::spawn_blocking(|| detect_active_vpn(None))
            .await
            .unwrap_or(VpnScope::None);
        let initial_action = vpn_guard.evaluate(&initial_scope, Instant::now());
        let mut last_warned_provider: Option<String> = None;

        match initial_action {
            GuardAction::YieldTun { provider } => {
                warn!(
                    provider = %provider,
                    "full-tunnel VPN active at startup; holding TUN in yielded standby until VPN disconnects"
                );
            }
            GuardAction::WarnOnly { provider } => {
                warn!(
                    provider = %provider,
                    "full-tunnel VPN detected (vpn_coexistence=warn); starting TUN mode anyway"
                );
                last_warned_provider = Some(provider);
                slot.start(&binder, cfg.tun_ipv6, &ctx, &tun_stats, &events)
                    .await?;
            }
            GuardAction::None | GuardAction::ResumeTun => {
                slot.start(&binder, cfg.tun_ipv6, &ctx, &tun_stats, &events)
                    .await?;
            }
        }

        if slot.is_running() {
            let probe_ctx = ctx.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(
                    Duration::from_secs(4),
                    probe_ctx.dns.resolve("cloudflare.com"),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        debug!("TUN outbound bound DNS probe succeeded");
                    }
                    Ok(Err(err)) => {
                        warn!(
                            error = %err,
                            "TUN outbound bound DNS probe failed - check physical uplink / firewall"
                        );
                    }
                    Err(_) => {
                        warn!(
                            error = "timed out after 4s",
                            "TUN outbound bound DNS probe failed - check physical uplink / firewall"
                        );
                    }
                }
            });
        }

        let health_listener = match bind_loopback_health_listener(DEFAULT_TUN_HEALTH_PORT) {
            Ok(listener) => listener,
            Err(err) => {
                slot.stop().await;
                let _ = ctx.flush_persisted_cache().await;
                return Err(err);
            }
        };
        let health_addr = match health_listener.local_addr() {
            Ok(addr) => addr,
            Err(err) => {
                slot.stop().await;
                let _ = ctx.flush_persisted_cache().await;
                return Err(err.into());
            }
        };

        let initial_iface = slot.iface_name().unwrap_or_else(|| "standby".to_string());
        let initial_nic = if slot.is_running() {
            binder
                .physical_nic_name()
                .or_else(|| slot.physical_nic_name())
        } else {
            None
        };
        let initial_vpn = vpn_guard.active_conflict_label(&initial_scope);

        let health_meta = Arc::new(Mutex::new(HealthRuntimeMeta {
            engine: EngineMode::Tun,
            tun_interface: Some(initial_iface.clone()),
            physical_nic: initial_nic.clone(),
            vpn_conflict: initial_vpn.clone(),
        }));

        write_runtime_state_with_meta(
            health_addr,
            None,
            EngineMode::Tun,
            Some(initial_iface.clone()),
            None,
        );

        let use_dashboard = dashboard_tracing.is_some();
        if !cfg.quiet {
            if !use_dashboard {
                print_tun_startup_banner(
                    &cfg,
                    &initial_iface,
                    initial_nic.as_deref(),
                    initial_vpn.as_deref(),
                    health_addr,
                );
            }
            info!(
                platform = platform_name(),
                engine = "tun",
                interface = %initial_iface,
                physical_nic = ?initial_nic,
                mode = ?cfg.mode,
                chunk_size = cfg.chunk_size,
                doh = cfg.enable_doh,
                vpn_coexistence = cfg.vpn_coexistence.as_str(),
                "vdpi desktop TUN engine active"
            );
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let health_meta_reader = Arc::clone(&health_meta);
        let health_binder_reader = Arc::clone(&binder);
        let meta_fn: HealthMetaFn = Arc::new(move || {
            let mut snapshot = health_meta_reader
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if snapshot
                .tun_interface
                .as_deref()
                .is_some_and(|iface| iface != "standby")
            {
                snapshot.physical_nic = health_binder_reader
                    .physical_nic_name()
                    .or(snapshot.physical_nic);
            } else {
                snapshot.physical_nic = None;
            }
            snapshot
        });
        let health_task = tokio::spawn(serve_health_until_shutdown(
            health_listener,
            ctx.clone(),
            meta_fn,
            shutdown_rx.clone(),
        ));

        let sup_env = TunStartEnv {
            binder: Arc::clone(&binder),
            ctx: ctx.clone(),
            tun_stats: Arc::clone(&tun_stats),
            events: Arc::clone(&events),
            tun_ipv6: cfg.tun_ipv6,
            health_addr,
        };
        let sup_meta = Arc::clone(&health_meta);
        let sup_shutdown_tx = shutdown_tx.clone();
        let mut sup_shutdown_rx = shutdown_rx.clone();
        let vpn_policy = cfg.vpn_coexistence;
        let mut last_scope = initial_scope;

        let supervisor_task: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
            let mut telemetry_tick = tokio::time::interval(Duration::from_millis(250));
            telemetry_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut vpn_tick = tokio::time::interval(Duration::from_secs(1));
            vpn_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            vpn_tick.tick().await;

            let mut retry = TunRetryState::new(slot.is_running());
            let mut fatal_error: Option<anyhow::Error> = None;

            loop {
                if *sup_shutdown_rx.borrow() {
                    break;
                }

                let event = {
                    let pipeline_task = &mut slot.pipeline_task;
                    #[cfg(any(target_os = "windows", target_os = "macos"))]
                    let route_rx = &mut slot.route_rx;
                    let slot_running = slot.session.is_some();

                    tokio::select! {
                        biased;
                        changed = sup_shutdown_rx.changed() => {
                            if changed.is_err() || *sup_shutdown_rx.borrow() {
                                break;
                            }
                            LoopEvent::None
                        }
                        pipeline_res = wait_pipeline_exit(pipeline_task) => {
                            if *sup_shutdown_rx.borrow() {
                                break;
                            }
                            if vpn_guard.is_yielded() {
                                LoopEvent::None
                            } else {
                                match &pipeline_res {
                                    Ok(()) => warn!(
                                        "TUN packet pipeline exited unexpectedly; tearing down adapter for recovery"
                                    ),
                                    Err(err) => error!(
                                        error = %err,
                                        "TUN packet pipeline failed; tearing down adapter for recovery"
                                    ),
                                }
                                let ran_healthy = retry
                                    .last_started_at
                                    .is_some_and(|t| t.elapsed() >= HEALTHY_PIPELINE_UPTIME);
                                if ran_healthy {
                                    retry.consecutive_pipeline_exits = 1;
                                    retry.consecutive_failures = 1;
                                } else {
                                    retry.consecutive_pipeline_exits =
                                        retry.consecutive_pipeline_exits.saturating_add(1);
                                    retry.consecutive_failures =
                                        retry.consecutive_failures.saturating_add(1);
                                }
                                retry.last_started_at = None;
                                if retry.consecutive_pipeline_exits >= MAX_CONSECUTIVE_PIPELINE_EXITS
                                {
                                    let reason = match pipeline_res {
                                        Ok(()) => anyhow::anyhow!(
                                            "TUN packet pipeline exited unexpectedly {} times in a row",
                                            retry.consecutive_pipeline_exits
                                        ),
                                        Err(err) => err.context(format!(
                                            "TUN packet pipeline failed {} times in a row",
                                            retry.consecutive_pipeline_exits
                                        )),
                                    };
                                    fatal_error = Some(reason);
                                    let _ = sup_shutdown_tx.send(true);
                                    break;
                                }
                                retry.next_retry_at =
                                    Some(Instant::now() + retry_backoff(retry.consecutive_failures));
                                LoopEvent::PipelineExited
                            }
                        }
                        _ = async {
                            #[cfg(any(target_os = "windows", target_os = "macos"))]
                            {
                                wait_route_change(route_rx).await;
                            }
                            #[cfg(not(any(target_os = "windows", target_os = "macos")))]
                            {
                                wait_route_change().await;
                            }
                        } => {
                            LoopEvent::Reconcile
                        }
                        _ = telemetry_tick.tick() => {
                            sync_tun_telemetry(&sup_env.ctx, &sup_env.tun_stats);
                            let mut meta = sup_meta.lock().unwrap_or_else(|e| e.into_inner());
                            meta.physical_nic = if slot_running {
                                sup_env.binder.physical_nic_name()
                            } else {
                                None
                            };
                            LoopEvent::None
                        }
                        _ = vpn_tick.tick() => {
                            if vpn_policy != VpnCoexistence::Off {
                                LoopEvent::Reconcile
                            } else if !slot_running {
                                LoopEvent::RetryStart
                            } else {
                                LoopEvent::None
                            }
                        }
                    }
                };

                if matches!(event, LoopEvent::PipelineExited) {
                    slot.stop().await;
                    write_runtime_state_with_meta(
                        sup_env.health_addr,
                        None,
                        EngineMode::Tun,
                        Some("standby".to_string()),
                        None,
                    );
                    update_health_meta(&sup_meta, &sup_env.binder, &slot, &vpn_guard, &last_scope);
                    if *sup_shutdown_rx.borrow() {
                        break;
                    }
                }

                match event {
                    LoopEvent::None => continue,
                    LoopEvent::RetryStart => {
                        let now = Instant::now();
                        if !slot.is_running() && retry.retry_due(now) {
                            match try_start_slot(
                                &mut slot,
                                &sup_env,
                                &sup_shutdown_rx,
                                &mut retry,
                                now,
                                "recovered TUN mode after pipeline restart",
                            )
                            .await
                            {
                                StartOutcome::Started | StartOutcome::RetryLater => {}
                                StartOutcome::Shutdown => break,
                                StartOutcome::Fatal(err) => {
                                    fatal_error = Some(err);
                                    let _ = sup_shutdown_tx.send(true);
                                    break;
                                }
                            }
                            update_health_meta(
                                &sup_meta,
                                &sup_env.binder,
                                &slot,
                                &vpn_guard,
                                &last_scope,
                            );
                        }
                        continue;
                    }
                    LoopEvent::Reconcile | LoopEvent::PipelineExited => {
                        if vpn_policy == VpnCoexistence::Off {
                            continue;
                        }
                    }
                }

                let self_iface = slot.iface_name();
                let scope =
                    tokio::task::spawn_blocking(move || detect_active_vpn(self_iface.as_deref()))
                        .await
                        .unwrap_or(VpnScope::None);
                if *sup_shutdown_rx.borrow() {
                    break;
                }
                let now = Instant::now();
                let action = vpn_guard.evaluate(&scope, now);
                last_scope = scope;

                match action {
                    GuardAction::YieldTun { provider } => {
                        last_warned_provider = None;
                        retry.record_yielded();
                        if slot.is_running() {
                            warn!(
                                provider = %provider,
                                "full-tunnel VPN active; yielding TUN routes and adapter cleanly"
                            );
                            slot.stop().await;
                            write_runtime_state_with_meta(
                                sup_env.health_addr,
                                None,
                                EngineMode::Tun,
                                Some("standby".to_string()),
                                None,
                            );
                        } else {
                            debug!(
                                provider = %provider,
                                "full-tunnel VPN active during recovery; keeping TUN in yielded standby"
                            );
                        }
                    }
                    GuardAction::ResumeTun => {
                        last_warned_provider = None;
                        retry.consecutive_pipeline_exits = 0;
                        if !slot.is_running() && retry.retry_due(now) {
                            match try_start_slot(
                                &mut slot,
                                &sup_env,
                                &sup_shutdown_rx,
                                &mut retry,
                                now,
                                "full-tunnel VPN cleared; resumed TUN mode",
                            )
                            .await
                            {
                                StartOutcome::Started | StartOutcome::RetryLater => {}
                                StartOutcome::Shutdown => break,
                                StartOutcome::Fatal(err) => {
                                    fatal_error = Some(err);
                                    let _ = sup_shutdown_tx.send(true);
                                    break;
                                }
                            }
                        }
                    }
                    GuardAction::WarnOnly { provider } => {
                        if last_warned_provider.as_deref() != Some(provider.as_str()) {
                            warn!(
                                provider = %provider,
                                "full-tunnel VPN detected while vpn_coexistence=warn"
                            );
                            last_warned_provider = Some(provider);
                        }
                        if !slot.is_running() && retry.retry_due(now) {
                            match try_start_slot(
                                &mut slot,
                                &sup_env,
                                &sup_shutdown_rx,
                                &mut retry,
                                now,
                                "recovered TUN mode after retry",
                            )
                            .await
                            {
                                StartOutcome::Started | StartOutcome::RetryLater => {}
                                StartOutcome::Shutdown => break,
                                StartOutcome::Fatal(err) => {
                                    fatal_error = Some(err);
                                    let _ = sup_shutdown_tx.send(true);
                                    break;
                                }
                            }
                        }
                    }
                    GuardAction::None => {
                        if !last_scope.is_full_tunnel() {
                            last_warned_provider = None;
                        }
                        if !vpn_guard.is_yielded() && !slot.is_running() && retry.retry_due(now) {
                            match try_start_slot(
                                &mut slot,
                                &sup_env,
                                &sup_shutdown_rx,
                                &mut retry,
                                now,
                                "resumed TUN mode after retry",
                            )
                            .await
                            {
                                StartOutcome::Started | StartOutcome::RetryLater => {}
                                StartOutcome::Shutdown => break,
                                StartOutcome::Fatal(err) => {
                                    fatal_error = Some(err);
                                    let _ = sup_shutdown_tx.send(true);
                                    break;
                                }
                            }
                        }
                    }
                }

                update_health_meta(&sup_meta, &sup_env.binder, &slot, &vpn_guard, &last_scope);
            }

            slot.stop().await;
            sync_tun_telemetry(&sup_env.ctx, &sup_env.tun_stats);
            match fatal_error {
                Some(err) => Err(err),
                None => Ok(()),
            }
        });

        let mut dash_shutdown_rx = shutdown_rx.clone();
        let combined_shutdown = async move {
            tokio::select! {
                _ = wait_for_shutdown_signal() => {}
                _ = async {
                    let _ = dash_shutdown_rx.wait_for(|stopped| *stopped).await;
                } => {}
            }
        };

        if let Some(dashboard) = dashboard_tracing {
            let dash_info = DashboardInfo {
                engine: DashboardEngine::Tun {
                    interface: initial_iface.clone(),
                    physical_nic: initial_nic.clone(),
                    vpn_conflict: initial_vpn.clone(),
                },
                mode: cfg.mode,
                enable_doh: cfg.enable_doh,
            };
            let probe_meta = Arc::clone(&health_meta);
            let probe_binder = Arc::clone(&binder);
            let tun_meta_probe: TunMetaProbe = Arc::new(move || {
                let meta = probe_meta.lock().unwrap_or_else(|e| e.into_inner());
                let active = meta
                    .tun_interface
                    .as_deref()
                    .is_some_and(|iface| iface != "standby");
                TunLiveMeta {
                    interface: meta.tun_interface.clone(),
                    physical_nic: if active {
                        probe_binder
                            .physical_nic_name()
                            .or_else(|| meta.physical_nic.clone())
                    } else {
                        None
                    },
                    vpn_conflict: meta.vpn_conflict.clone(),
                }
            });

            if let Err(err) = tui_dashboard::run_dashboard_with_tun_meta(
                dash_info,
                ctx.clone(),
                dashboard.logs,
                shutdown_tx.clone(),
                combined_shutdown,
                Some(tun_meta_probe),
            )
            .await
            {
                dashboard
                    .passthrough_stderr
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                eprintln!("vdpi dashboard unavailable ({err}); running in headless mode");
                if !cfg.quiet {
                    print_tun_startup_banner(
                        &cfg,
                        &initial_iface,
                        initial_nic.as_deref(),
                        initial_vpn.as_deref(),
                        health_addr,
                    );
                }
                let mut fallback_rx = shutdown_rx.clone();
                tokio::select! {
                    _ = wait_for_shutdown_signal() => {}
                    _ = async {
                        let _ = fallback_rx.wait_for(|stopped| *stopped).await;
                    } => {}
                }
            }
        } else {
            combined_shutdown.await;
        }

        info!("received shutdown signal; stopping vdpi TUN engine cleanly");
        let _ = shutdown_tx.send(true);
        clear_runtime_state(std::process::id());

        let supervisor_result = match tokio::time::timeout(Duration::from_secs(12), supervisor_task)
            .await
        {
            Ok(Ok(res)) => res,
            Ok(Err(join_err)) => Err(anyhow::anyhow!("TUN supervisor task panicked: {join_err}")),
            Err(_) => {
                warn!("timed out after 12s waiting for TUN supervisor cleanup");
                Ok(())
            }
        };
        let _ = tokio::time::timeout(Duration::from_secs(2), health_task).await;
        if let Err(err) = ctx.flush_persisted_cache().await {
            debug!(error = %err, "failed to flush adaptive cache on TUN shutdown");
        }
        supervisor_result
    }

    fn print_tun_startup_banner(
        cfg: &RuntimeConfig,
        iface: &str,
        physical_nic: Option<&str>,
        vpn_conflict: Option<&str>,
        health_addr: SocketAddr,
    ) {
        println!(
            "\n  __   ____| |_ __ (_)\n  \\ \\ / / _` | '_ \\| |\n   \\ V / (_| | |_) | |\n    \\_/ \\__,_| .__/|_|\n             |_|        v{} ({})\n",
            env!("CARGO_PKG_VERSION"),
            platform_name()
        );
        println!("  Engine              : Transparent TUN ({iface})");
        if let Some(nic) = physical_nic {
            println!("  Physical Uplink     : {nic}");
        }
        println!("  Health Endpoint     : http://{health_addr}/vdpi-health");
        println!(
            "  Desync Engine       : {:?} ({}-byte SNI segments + 7-stage OOB/record auto-heal)",
            cfg.mode, cfg.chunk_size
        );
        println!(
            "  DNS Resolution      : {}",
            if cfg.enable_doh {
                format!("RFC 8484 DoH ({}) + non-53 UDP fallback", cfg.dns_addr)
            } else {
                format!("UDP ({}:{})", cfg.dns_addr, cfg.dns_port)
            }
        );
        println!("  VPN Coexistence     : {}", cfg.vpn_coexistence.as_str());
        if let Some(vpn) = vpn_conflict {
            println!("  VPN Status          : {vpn}");
        }
        println!();
    }
}

fn print_startup_banner(
    cfg: &RuntimeConfig,
    primary_addr: std::net::SocketAddr,
    socks_addr: Option<std::net::SocketAddr>,
    proxy_summary: Option<&str>,
) {
    println!(
        "\n  __   ____| |_ __ (_)\n  \\ \\ / / _` | '_ \\| |\n   \\ V / (_| | |_) | |\n    \\_/ \\__,_| .__/|_|\n             |_|        v{} ({})\n",
        env!("CARGO_PKG_VERSION"),
        platform_name()
    );
    println!("  HTTP / HTTPS / Auto : {}", primary_addr);
    if let Some(sa) = socks_addr {
        println!("  SOCKS5 (TCP + UDP)  : {sa}");
    }
    println!(
        "  Desync Engine       : {:?} ({}-byte SNI segments + 7-stage OOB/record auto-heal)",
        cfg.mode, cfg.chunk_size
    );
    println!(
        "  DNS Resolution      : {}",
        if cfg.enable_doh {
            format!("RFC 8484 DoH ({}) + non-53 UDP fallback", cfg.dns_addr)
        } else {
            format!("UDP ({}:{})", cfg.dns_addr, cfg.dns_port)
        }
    );
    println!(
        "  System Integration  : {}\n",
        proxy_summary.unwrap_or("disabled (--no-system-proxy)")
    );
    #[cfg(windows)]
    if cfg.system_proxy && cfg.env_proxy {
        println!(
            "  Desktop Apps Note   : Restart any already-open browser once if launching games (e.g. Roblox) from it,\n                        or run `vdpi install` so HTTPS_PROXY is inherited automatically at login.\n"
        );
    }
}

fn init_tracing(cfg: &RuntimeConfig) {
    if cfg.quiet && !cfg.debug {
        return;
    }
    let default_level = if cfg.debug { "vdpi=debug" } else { "vdpi=info" };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .try_init();
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn is_service_mode(cfg: &RuntimeConfig) -> bool {
    #[cfg(target_os = "windows")]
    {
        cfg.windows_service || vdpi::platform::windows::is_running_as_service()
    }
    #[cfg(not(target_os = "windows"))]
    {
        cfg.windows_service
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn init_tui_tracing() -> DashboardTracing {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let logs = tui_dashboard::new_log_ring();
    let passthrough_stderr = Arc::new(AtomicBool::new(false));
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("vdpi=info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(tui_dashboard::TuiLogLayer::new(
            Arc::clone(&logs),
            Arc::clone(&passthrough_stderr),
        ))
        .try_init();
    DashboardTracing {
        logs,
        passthrough_stderr,
    }
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, Signal, SignalKind};

        async fn wait_signal(sig: &mut Option<Signal>) {
            match sig.as_mut() {
                Some(s) => {
                    let _ = s.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        }

        let mut sigterm = signal(SignalKind::terminate()).ok();
        let mut sigint = signal(SignalKind::interrupt()).ok();
        let mut sighup = signal(SignalKind::hangup()).ok();

        if sigterm.is_none() && sigint.is_none() && sighup.is_none() {
            let _ = tokio::signal::ctrl_c().await;
            return;
        }

        tokio::select! {
            _ = wait_signal(&mut sigterm) => {}
            _ = wait_signal(&mut sigint) => {}
            _ = wait_signal(&mut sighup) => {}
        }
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_shutdown};

        let mut sig_c = ctrl_c().ok();
        let mut sig_break = ctrl_break().ok();
        let mut sig_close = ctrl_close().ok();
        let mut sig_shutdown = ctrl_shutdown().ok();

        if sig_c.is_none() && sig_break.is_none() && sig_close.is_none() && sig_shutdown.is_none() {
            let _ = tokio::signal::ctrl_c().await;
            return;
        }

        tokio::select! {
            _ = async {
                match sig_c.as_mut() {
                    Some(s) => {
                        let _ = s.recv().await;
                    }
                    None => std::future::pending::<()>().await,
                }
            } => {}
            _ = async {
                match sig_break.as_mut() {
                    Some(s) => {
                        let _ = s.recv().await;
                    }
                    None => std::future::pending::<()>().await,
                }
            } => {}
            _ = async {
                match sig_close.as_mut() {
                    Some(s) => {
                        let _ = s.recv().await;
                    }
                    None => std::future::pending::<()>().await,
                }
            } => {}
            _ = async {
                match sig_shutdown.as_mut() {
                    Some(s) => {
                        let _ = s.recv().await;
                    }
                    None => std::future::pending::<()>().await,
                }
            } => {}
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn raise_fd_limit() {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    unsafe {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 {
            const TARGET_NOFILE: libc::rlim_t = 65536;
            let target = TARGET_NOFILE.min(lim.rlim_max);
            if lim.rlim_cur < target {
                lim.rlim_cur = target;
                let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_notice_collapses_multiline_and_tabs() {
        assert_eq!(
            sanitize_notice("Pause failed:\r\n\taccess\ndenied\x07  now"),
            "Pause failed: access denied now"
        );
        assert_eq!(sanitize_notice("  ok\n"), "ok");
    }

    #[test]
    fn get_or_init_cli_runtime_reuses_single_instance() {
        let mut slot: Option<tokio::runtime::Runtime> = None;
        let first_val = get_or_init_cli_runtime(&mut slot)
            .unwrap()
            .block_on(async { 41usize + 1 });
        assert_eq!(first_val, 42);
        let first_ptr: *const tokio::runtime::Runtime = slot.as_ref().unwrap();
        let second_ptr: *const tokio::runtime::Runtime =
            get_or_init_cli_runtime(&mut slot).unwrap();
        assert_eq!(first_ptr, second_ptr);
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn tun_start_error_includes_actionable_proxy_fallback() {
        let missing_dll = desktop_tun::format_tun_start_error(anyhow::anyhow!(
            "wintun.dll not found next to executable"
        ));
        let msg = missing_dll.to_string();
        assert!(msg.contains("--proxy"));

        let priv_err =
            desktop_tun::format_tun_start_error(anyhow::anyhow!("Access is denied (os error 5)"));
        assert!(priv_err.to_string().contains("--proxy"));
    }

    #[test]
    fn config_command_set_unset_validate_and_reset_roundtrip() {
        let dir = std::env::temp_dir().join(format!("vdpi-main-cfg-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg_path = dir.join("config.toml");
        let cfg_str = cfg_path.to_string_lossy().into_owned();

        let set_cli = CliArgs::parse_from_iter([
            "vdpi", "--config", &cfg_str, "config", "set", "engine", "tun",
        ])
        .unwrap();
        let set_action = match set_cli.command.clone() {
            Some(Command::Config { action }) => action,
            other => panic!("unexpected command: {other:?}"),
        };
        handle_config_command(set_action, set_cli, &[]).unwrap();

        let (found, loaded) = load_file_config(Some(&cfg_path), false).unwrap();
        assert_eq!(found.as_deref(), Some(cfg_path.as_path()));
        assert_eq!(loaded.engine, Some(EngineMode::Tun));

        let unset_cli =
            CliArgs::parse_from_iter(["vdpi", "--config", &cfg_str, "config", "unset", "engine"])
                .unwrap();
        let unset_action = match unset_cli.command.clone() {
            Some(Command::Config { action }) => action,
            other => panic!("unexpected command: {other:?}"),
        };
        handle_config_command(unset_action, unset_cli, &[]).unwrap();

        let (_, after_unset) = load_file_config(Some(&cfg_path), false).unwrap();
        assert_eq!(after_unset.engine, None);

        let reset_cli =
            CliArgs::parse_from_iter(["vdpi", "--config", &cfg_str, "config", "reset"]).unwrap();
        let reset_action = match reset_cli.command.clone() {
            Some(Command::Config { action }) => action,
            other => panic!("unexpected command: {other:?}"),
        };
        handle_config_command(reset_action, reset_cli, &[]).unwrap();

        let (_, after_reset) = load_file_config(Some(&cfg_path), false).unwrap();
        assert_eq!(after_reset.schema_version, Some(CONFIG_SCHEMA_VERSION));
        assert_eq!(after_reset.engine, None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_command_unset_missing_file_does_not_create_file() {
        let dir = std::env::temp_dir().join(format!(
            "vdpi-main-cfg-unset-missing-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg_path = dir.join("config.toml");
        let cfg_str = cfg_path.to_string_lossy().into_owned();

        let unset_cli =
            CliArgs::parse_from_iter(["vdpi", "--config", &cfg_str, "config", "unset", "engine"])
                .unwrap();
        let unset_action = match unset_cli.command.clone() {
            Some(Command::Config { action }) => action,
            other => panic!("unexpected command: {other:?}"),
        };
        handle_config_command(unset_action, unset_cli, &[]).unwrap();
        assert!(!cfg_path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_command_set_validates_chunk_size_and_bypass_policy_and_get_works() {
        let dir =
            std::env::temp_dir().join(format!("vdpi-main-cfg-validate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg_path = dir.join("config.toml");
        let cfg_str = cfg_path.to_string_lossy().into_owned();

        let bad_chunk_cli = CliArgs::parse_from_iter([
            "vdpi",
            "--config",
            &cfg_str,
            "config",
            "set",
            "chunk_size",
            "0",
        ])
        .unwrap();
        let bad_chunk_action = match bad_chunk_cli.command.clone() {
            Some(Command::Config { action }) => action,
            other => panic!("unexpected command: {other:?}"),
        };
        assert!(handle_config_command(bad_chunk_action, bad_chunk_cli, &[]).is_err());
        assert!(!cfg_path.exists());

        let bad_regex_cli = CliArgs::parse_from_iter([
            "vdpi",
            "--config",
            &cfg_str,
            "config",
            "set",
            "include_domains",
            "[unclosed",
        ])
        .unwrap();
        let bad_regex_action = match bad_regex_cli.command.clone() {
            Some(Command::Config { action }) => action,
            other => panic!("unexpected command: {other:?}"),
        };
        assert!(handle_config_command(bad_regex_action, bad_regex_cli, &[]).is_err());
        assert!(!cfg_path.exists());

        let set_cli = CliArgs::parse_from_iter([
            "vdpi", "--config", &cfg_str, "config", "set", "engine", "tun",
        ])
        .unwrap();
        let set_action = match set_cli.command.clone() {
            Some(Command::Config { action }) => action,
            other => panic!("unexpected command: {other:?}"),
        };
        handle_config_command(set_action, set_cli, &[]).unwrap();

        let get_cli =
            CliArgs::parse_from_iter(["vdpi", "--config", &cfg_str, "config", "get", "engine"])
                .unwrap();
        let get_action = match get_cli.command.clone() {
            Some(Command::Config { action }) => action,
            other => panic!("unexpected command: {other:?}"),
        };
        handle_config_command(get_action, get_cli, &[]).unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn normalize_system_proxy_addr_rewrites_unspecified_ips() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

        assert_eq!(
            normalize_system_proxy_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080)),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
        );
        assert_eq!(
            normalize_system_proxy_addr(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 8080)),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080)
        );
        let lan = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 8080);
        assert_eq!(normalize_system_proxy_addr(lan), lan);
    }

    #[test]
    fn format_live_engine_line_reports_standby_and_yielded_states() {
        use std::net::{IpAddr, Ipv4Addr};

        let base = vdpi::service::LiveEngineStatus {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
            socks_port: Some(1080),
            engine: EngineMode::Tun,
            tun_interface: Some("vdpi0".to_string()),
            physical_nic: Some("Wi-Fi".to_string()),
            vpn_conflict: None,
            version: None,
            mode: None,
            doh: None,
            block_quic: None,
            active_connections: None,
            total_connections: None,
            learned_hosts: None,
            isp_stage: None,
            udp_flows_active: None,
            quic_blocked: None,
            dns_queries: None,
            rss_kb: None,
            bytes_rx: None,
            bytes_tx: None,
            tls_handshakes: None,
            auto_heal_escalations: None,
        };
        assert_eq!(
            format_live_engine_line(&base),
            "Engine: tun (active, vdpi0 via Wi-Fi)"
        );

        let mut standby_none = base.clone();
        standby_none.tun_interface = None;
        standby_none.physical_nic = None;
        assert_eq!(
            format_live_engine_line(&standby_none),
            "Engine: tun (standby)"
        );

        let mut yielded = base.clone();
        yielded.tun_interface = Some("standby".to_string());
        yielded.physical_nic = None;
        yielded.vpn_conflict = Some("Mullvad (yielded)".to_string());
        assert_eq!(
            format_live_engine_line(&yielded),
            "Engine: tun (yielded, Mullvad (yielded))"
        );

        let mut proxy = base;
        proxy.engine = EngineMode::Proxy;
        assert_eq!(
            format_live_engine_line(&proxy),
            "Engine: proxy (active, 127.0.0.1:8080)"
        );
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn tun_retry_backoff_is_bounded() {
        assert_eq!(desktop_tun::retry_backoff(1), Duration::from_secs(3));
        assert_eq!(desktop_tun::retry_backoff(2), Duration::from_secs(6));
        assert_eq!(desktop_tun::retry_backoff(3), Duration::from_secs(12));
        assert_eq!(desktop_tun::retry_backoff(4), Duration::from_secs(24));
        assert_eq!(desktop_tun::retry_backoff(5), Duration::from_secs(30));
        assert_eq!(desktop_tun::retry_backoff(100), Duration::from_secs(30));
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn live_engine_status_maps_to_attached_dashboard_telemetry() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use vdpi::config::DesyncMode;

        let fallback_cfg = RuntimeConfig::default();
        let tun_live = vdpi::service::LiveEngineStatus {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 19847,
            socks_port: None,
            engine: EngineMode::Tun,
            tun_interface: Some("vdpi0".to_string()),
            physical_nic: Some("Ethernet".to_string()),
            vpn_conflict: None,
            version: Some("0.5.5".to_string()),
            mode: Some("tls-record".to_string()),
            doh: Some(false),
            block_quic: Some(true),
            active_connections: Some(7),
            total_connections: Some(42),
            learned_hosts: Some(5),
            isp_stage: Some("Stage 2".to_string()),
            udp_flows_active: Some(3),
            quic_blocked: Some(19),
            dns_queries: Some(88),
            rss_kb: Some(12288),
            bytes_rx: Some(65_536),
            bytes_tx: Some(16_384),
            tls_handshakes: Some(21),
            auto_heal_escalations: Some(2),
        };

        let info = dashboard_info_from_live(&tun_live, &fallback_cfg);
        assert_eq!(info.mode, DesyncMode::TlsRecord);
        assert!(!info.enable_doh);
        assert_eq!(
            info.engine,
            tui_dashboard::DashboardEngine::Tun {
                interface: "vdpi0".to_string(),
                physical_nic: Some("Ethernet".to_string()),
                vpn_conflict: None,
            }
        );

        let attached = attached_telemetry_from_live(&tun_live, &fallback_cfg);
        assert_eq!(attached.snap.active_connections, 7);
        assert_eq!(attached.snap.total_connections, 42);
        assert_eq!(attached.snap.bytes_rx, 65_536);
        assert_eq!(attached.snap.bytes_tx, 16_384);
        assert_eq!(attached.snap.tls_handshakes, 21);
        assert_eq!(attached.snap.auto_heal_escalations, 2);
        assert_eq!(attached.snap.learned_hosts, 5);
        assert_eq!(attached.snap.udp_flows_active, 3);
        assert_eq!(attached.snap.quic_blocked, 19);
        assert_eq!(attached.snap.dns_queries, 88);
        assert_eq!(attached.rss_kb, Some(12288));
        assert_eq!(attached.isp_stage.as_deref(), Some("Stage 2"));
        assert_eq!(attached.version.as_deref(), Some("0.5.5"));

        let mut proxy_live = tun_live;
        proxy_live.engine = EngineMode::Proxy;
        proxy_live.port = 8080;
        proxy_live.socks_port = Some(1080);
        proxy_live.mode = None;
        let proxy_info = dashboard_info_from_live(&proxy_live, &fallback_cfg);
        assert_eq!(proxy_info.mode, fallback_cfg.mode);
        assert_eq!(
            proxy_info.engine,
            tui_dashboard::DashboardEngine::Proxy {
                primary_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                socks_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080)),
                system_proxy: fallback_cfg.system_proxy,
            }
        );
    }

    #[test]
    fn split_tunnel_app_merge_and_remove_normalize_and_deduplicate() {
        let existing = vec!["Discord.exe".to_string(), "steam.exe".to_string()];
        let merged = merge_split_tunnel_apps(
            &existing,
            &[
                "discord".to_string(),
                "  firefox.exe ".to_string(),
                "FIREFOX".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(
            merged,
            vec![
                "Discord.exe".to_string(),
                "steam.exe".to_string(),
                "firefox.exe".to_string()
            ]
        );

        assert!(merge_split_tunnel_apps(&existing, &["   ".to_string()]).is_err());

        let remaining =
            remove_split_tunnel_apps(&merged, &["discord".to_string(), "STEAM.EXE".to_string()]);
        assert_eq!(remaining, vec!["firefox.exe".to_string()]);
    }
}
