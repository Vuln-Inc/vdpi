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
    clear_runtime_state, install_service_quiet, install_service_with_engine_override,
    print_status_with_options_and_config, run_doctor, switch_service_engine,
    switch_service_engine_quiet, uninstall_service_quiet, uninstall_service_with_options,
    write_runtime_state, ServiceState,
};

mod launcher;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod tui_dashboard;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod tui_tools;

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

    let res = run_main();
    if let Err(ref err) = res {
        if err
            .chain()
            .any(|cause| cause.is::<ApplyFileRestartError>())
        {
            eprintln!("Error: {err:#}");
            std::process::exit(EXIT_CODE_APPLY_RESTART_FAILED);
        }
        launcher::pause_on_own_console(&format!("{err:#}"));
    }
    res
}

fn run_main() -> Result<()> {
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
    if let Some(Command::Split { action }) = cli.command.clone() {
        return handle_split_command(
            action,
            cli.config_path.as_deref(),
            cli.split_mode,
            &cli.split_apps,
        );
    }

    let resilient_admin_cmd = matches!(
        cli.command,
        Some(Command::Uninstall { .. } | Command::Pause | Command::Resume)
    );
    let effective_service_mode =
        cli.service || (cli.config_path.is_none() && has_installed_system_service());
    let (_loaded_config_path, file_cfg) = match load_file_config(
        cli.config_path.as_deref(),
        effective_service_mode,
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
    let user_lang_cfg = if cli.config_path.is_none() {
        load_file_config(Some(&user_config_path()), false)
            .ok()
            .and_then(|(found, cfg)| found.map(|_| cfg))
    } else {
        None
    };
    seed_i18n_language_pref(&file_cfg, user_lang_cfg.as_ref(), cli.config_path.is_some());
    let explicit_config_path = cli.config_path.clone();
    let explicit_engine = if cli.tun {
        Some(EngineMode::Tun)
    } else if cli.proxy {
        Some(EngineMode::Proxy)
    } else {
        None
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

    let mut unattended = false;
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
                                launcher::tr(
                                    "Background service is already running. Pause it first before starting foreground TUN mode.",
                                    "Arka plan servisi zaten çalışıyor. Ön plan TUN modunu başlatmadan önce duraklatın.",
                                )
                                .to_string(),
                            );
                            explicit_launcher = true;
                            continue;
                        } else if cfg.system_proxy {
                            notice = Some(
                                launcher::tr(
                                    "Background service is already running. Pause it first or run with --no-system-proxy.",
                                    "Arka plan servisi zaten çalışıyor. Önce duraklatın veya --no-system-proxy ile çalıştırın.",
                                )
                                .to_string(),
                            );
                            explicit_launcher = true;
                            continue;
                        }
                    }
                    #[cfg(target_os = "windows")]
                    if cfg.engine == EngineMode::Tun {
                        if let Err(msg) = preflight_windows_wintun_dll() {
                            notice = Some(msg);
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
                                notice = Some(sanitize_notice(&format!(
                                    "{}: {err:#}",
                                    launcher::tr("TUN start failed", "TUN başlatma başarısız")
                                )));
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
                                notice = Some(sanitize_notice(&format!(
                                    "{}: {err:#}",
                                    launcher::tr("TUN start failed", "TUN başlatma başarısız")
                                )));
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
                    unattended = true;
                    command = Some(Command::Start);
                    break;
                }
                launcher::Choice::Install => {
                    #[cfg(target_os = "windows")]
                    if cfg.engine == EngineMode::Tun {
                        if let Err(msg) = preflight_windows_wintun_dll() {
                            notice = Some(msg);
                            explicit_launcher = true;
                            continue;
                        }
                    }
                    match install_service_quiet(&cfg) {
                        Ok(()) => {
                            launcher::clear_preference();
                            session_engine_override = None;
                            wait_for_live_engine(&cfg, cfg.engine);
                            notice = Some(if installed_before.is_some() {
                                match launcher::active_lang() {
                                    vdpi::i18n::Lang::En => format!(
                                        "Updated vdpi background service to v{}.",
                                        env!("CARGO_PKG_VERSION")
                                    ),
                                    vdpi::i18n::Lang::Tr => format!(
                                        "vdpi arka plan servisi v{} sürümüne güncellendi.",
                                        env!("CARGO_PKG_VERSION")
                                    ),
                                }
                            } else {
                                launcher::tr(
                                    "vdpi installed and running in background.",
                                    "vdpi kuruldu ve arka planda çalışıyor.",
                                )
                                .to_string()
                            });
                        }
                        Err(err) => {
                            notice = Some(sanitize_notice(&format!(
                                "{}: {err:#}",
                                launcher::tr("Install failed", "Kurulum başarısız")
                            )));
                        }
                    }
                    explicit_launcher = true;
                    continue;
                }
                launcher::Choice::Update => {
                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                    {
                        let result = get_or_init_cli_runtime(&mut cli_rt)
                            .and_then(|rt| rt.block_on(tui_tools::run_update_tui(&cfg)));
                        match result {
                            Ok(Some(msg)) => {
                                launcher::clear_preference();
                                notice = Some(sanitize_notice(&msg));
                            }
                            Ok(None) => {
                                notice = None;
                            }
                            Err(err) => {
                                notice = Some(sanitize_notice(&format!(
                                    "{}: {err:#}",
                                    launcher::tr("Update failed", "Güncelleme başarısız")
                                )));
                            }
                        }
                    }
                    #[cfg(any(target_os = "android", target_os = "ios"))]
                    {
                        let result = get_or_init_cli_runtime(&mut cli_rt).and_then(|rt| {
                            rt.block_on(vdpi::update::run_update(false, false, &cfg))
                        });
                        match result {
                            Ok(()) => {
                                launcher::clear_preference();
                                notice = Some(
                                    launcher::tr(
                                        "Update check complete.",
                                        "Güncelleme denetimi tamamlandı.",
                                    )
                                    .to_string(),
                                );
                            }
                            Err(err) => {
                                notice = Some(sanitize_notice(&format!(
                                    "{}: {err:#}",
                                    launcher::tr("Update failed", "Güncelleme başarısız")
                                )));
                            }
                        }
                    }
                    explicit_launcher = true;
                    continue;
                }
                launcher::Choice::PauseService => {
                    match vdpi::service::pause_service_quiet() {
                        Ok(()) => {
                            notice = Some(
                                launcher::tr(
                                    "Service paused - system proxies restored.",
                                    "Servis duraklatıldı - sistem proxy ayarları geri yüklendi.",
                                )
                                .to_string(),
                            );
                        }
                        Err(err) => {
                            notice = Some(sanitize_notice(&format!(
                                "{}: {err:#}",
                                launcher::tr("Pause failed", "Duraklatma başarısız")
                            )));
                        }
                    }
                    explicit_launcher = true;
                }
                launcher::Choice::ResumeService => {
                    #[cfg(target_os = "windows")]
                    if status.configured_engine == EngineMode::Tun {
                        if let Err(msg) = preflight_windows_wintun_dll() {
                            notice = Some(msg);
                            explicit_launcher = true;
                            continue;
                        }
                    }
                    match vdpi::service::resume_service_quiet() {
                        Ok(()) => {
                            wait_for_live_engine(&cfg, status.configured_engine);
                            notice = Some(
                                launcher::tr(
                                    "Service resumed - anti-DPI active.",
                                    "Servis sürdürüldü - anti-DPI etkin.",
                                )
                                .to_string(),
                            );
                        }
                        Err(err) => {
                            notice = Some(sanitize_notice(&format!(
                                "{}: {err:#}",
                                launcher::tr("Resume failed", "Sürdürme başarısız")
                            )));
                        }
                    }
                    explicit_launcher = true;
                }
                launcher::Choice::SwitchEngine(target) => {
                    #[cfg(target_os = "windows")]
                    if target == EngineMode::Tun {
                        if let Err(msg) = preflight_windows_wintun_dll() {
                            notice = Some(msg);
                            explicit_launcher = true;
                            continue;
                        }
                    }
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
                                    EngineMode::Tun => launcher::tr(
                                        "Switched to TUN mode.",
                                        "TUN moduna geçildi.",
                                    ),
                                    EngineMode::Proxy => launcher::tr(
                                        "Switched to Proxy mode.",
                                        "Proxy moduna geçildi.",
                                    ),
                                };
                                notice = Some(msg.to_string());
                            }
                            Err(err) => {
                                notice = Some(sanitize_notice(&format!(
                                    "{}: {err:#}",
                                    launcher::tr(
                                        "Engine switch failed",
                                        "Motor değiştirme başarısız"
                                    )
                                )));
                            }
                        }
                    } else {
                        cfg.engine = target;
                        session_engine_override = Some(target);
                        let user_path = user_config_path();
                        let save_res = load_file_config_or_default(Some(&user_path), false)
                            .and_then(|(_, mut fc)| {
                                fc.schema_version = Some(CONFIG_SCHEMA_VERSION);
                                fc.engine = Some(target);
                                save_config_with_ownership(&user_path, &fc)
                            });
                        let base_msg = match target {
                            EngineMode::Tun => launcher::tr(
                                "Engine set to TUN mode.",
                                "Motor TUN moduna ayarlandı.",
                            ),
                            EngineMode::Proxy => launcher::tr(
                                "Engine set to Proxy mode.",
                                "Motor Proxy moduna ayarlandı.",
                            ),
                        };
                        notice = Some(match save_res {
                            Ok(()) => base_msg.to_string(),
                            Err(err) => sanitize_notice(&match launcher::active_lang() {
                                vdpi::i18n::Lang::En => {
                                    format!("{base_msg} (warning: failed to save config: {err:#})")
                                }
                                vdpi::i18n::Lang::Tr => {
                                    format!("{base_msg} (uyarı: yapılandırma kaydedilemedi: {err:#})")
                                }
                            }),
                        });
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
                    let was_running = status.service_state == ServiceState::Running;
                    let target_engine = status
                        .live_engine
                        .as_ref()
                        .map_or(status.configured_engine, |live| live.engine);
                    match resolve_dns_target(&dns_addr).and_then(|validated| {
                        vdpi::service::set_service_dns_quiet(&validated, &cfg).map(|()| validated)
                    }) {
                        Ok(validated) => {
                            let label = launcher::format_dns_label(&validated);
                            cfg.enable_doh =
                                vdpi_core::dns::effective_enable_doh(&validated, cfg.enable_doh);
                            cfg.dns_addr = validated.clone();
                            session_dns_override = Some(validated);
                            if was_running {
                                wait_for_live_engine(&cfg, target_engine);
                            }
                            notice = Some(match (launcher::active_lang(), was_installed) {
                                (vdpi::i18n::Lang::En, true) => {
                                    format!("DNS server set to {label}.")
                                }
                                (vdpi::i18n::Lang::En, false) => {
                                    format!("DNS server set to {label} (saved).")
                                }
                                (vdpi::i18n::Lang::Tr, true) => {
                                    format!("DNS sunucusu {label} olarak ayarlandı.")
                                }
                                (vdpi::i18n::Lang::Tr, false) => {
                                    format!("DNS sunucusu {label} olarak ayarlandı (kaydedildi).")
                                }
                            });
                        }
                        Err(err) => {
                            notice = Some(sanitize_notice(&format!(
                                "{}: {err:#}",
                                launcher::tr("DNS change failed", "DNS değiştirme başarısız")
                            )));
                        }
                    }
                    explicit_launcher = true;
                    continue;
                }
                launcher::Choice::SplitTunnel => {
                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                    {
                        let was_running = status.service_state == ServiceState::Running;
                        let target_engine = status
                            .live_engine
                            .as_ref()
                            .map_or(status.configured_engine, |live| live.engine);
                        match vdpi::split_tunnel::tui::run_split_tunnel_picker(configured_split) {
                            Ok(Some(new_cfg)) => {
                                match vdpi::service::set_service_split_tunnel(&new_cfg) {
                                    Ok(msg) => {
                                        let restarted =
                                            was_running || msg.contains("service restarted");
                                        let saved_notice =
                                            format_split_tunnel_saved_notice(&new_cfg, restarted);
                                        cfg.split_tunnel = new_cfg.clone();
                                        session_split_override = Some(new_cfg);
                                        if was_running {
                                            wait_for_live_engine(&cfg, target_engine);
                                        }
                                        notice = Some(sanitize_notice(&saved_notice));
                                    }
                                    Err(err) => {
                                        notice = Some(sanitize_notice(&format!(
                                            "{}: {err:#}",
                                            launcher::tr(
                                                "Split tunnel save failed",
                                                "Bölünmüş tünel kaydetme başarısız"
                                            )
                                        )));
                                    }
                                }
                            }
                            Ok(None) => {
                                notice = None;
                            }
                            Err(err) => {
                                notice = Some(sanitize_notice(&format!(
                                    "{}: {err:#}",
                                    launcher::tr(
                                        "Split tunnel picker failed",
                                        "Bölünmüş tünel seçici başarısız"
                                    )
                                )));
                            }
                        }
                    }
                    #[cfg(any(target_os = "android", target_os = "ios"))]
                    {
                        notice = Some(
                            launcher::tr(
                                "Split tunnel picker is not supported on this platform.",
                                "Bölünmüş tünel seçici bu platformda desteklenmiyor.",
                            )
                            .to_string(),
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
                                notice = Some(
                                    launcher::tr(
                                        "No running vdpi service detected.",
                                        "Çalışan vdpi servisi bulunamadı.",
                                    )
                                    .to_string(),
                                );
                            }
                            Err(err) => {
                                notice = Some(sanitize_notice(&format!(
                                    "{}: {err:#}",
                                    launcher::tr("Dashboard error", "Panel hatası")
                                )));
                            }
                        }
                    }
                    #[cfg(any(target_os = "android", target_os = "ios"))]
                    {
                        notice = Some(
                            launcher::tr(
                                "Live dashboard is not supported on this platform.",
                                "Canlı panel bu platformda desteklenmiyor.",
                            )
                            .to_string(),
                        );
                    }
                    explicit_launcher = true;
                    continue;
                }
                launcher::Choice::Doctor => {
                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                    {
                        let result = get_or_init_cli_runtime(&mut cli_rt).and_then(|rt| {
                            rt.block_on(tui_tools::run_diagnostics_tui(cfg.clone()))
                        });
                        match result {
                            Ok(summary) => {
                                notice = Some(sanitize_notice(&summary));
                            }
                            Err(err) => {
                                notice = Some(sanitize_notice(&format!(
                                    "{}: {err:#}",
                                    launcher::tr("Diagnostics failed", "Tanılama başarısız")
                                )));
                            }
                        }
                    }
                    #[cfg(any(target_os = "android", target_os = "ios"))]
                    {
                        let result = get_or_init_cli_runtime(&mut cli_rt)
                            .and_then(|rt| rt.block_on(run_doctor(cfg.clone())));
                        match result {
                            Ok(()) => {
                                notice = Some(
                                    launcher::tr("Diagnostics complete.", "Tanılama tamamlandı.")
                                        .to_string(),
                                );
                            }
                            Err(err) => {
                                notice = Some(sanitize_notice(&format!(
                                    "{}: {err:#}",
                                    launcher::tr("Diagnostics failed", "Tanılama başarısız")
                                )));
                            }
                        }
                    }
                    explicit_launcher = true;
                    continue;
                }
                launcher::Choice::Uninstall => {
                    match uninstall_service_quiet() {
                        Ok(()) => {
                            launcher::clear_preference();
                            session_engine_override = None;
                            session_dns_override = None;
                            session_split_override = None;
                            notice = Some(
                                launcher::tr(
                                    "vdpi background service uninstalled.",
                                    "vdpi arka plan servisi kaldırıldı.",
                                )
                                .to_string(),
                            );
                        }
                        Err(err) => {
                            notice = Some(sanitize_notice(&format!(
                                "{}: {err:#}",
                                launcher::tr("Uninstall failed", "Kaldırma başarısız")
                            )));
                        }
                    }
                    explicit_launcher = true;
                    continue;
                }
                launcher::Choice::Cancel => return Ok(()),
            }
        }
    }

    match command {
        Some(Command::Install { upgrade }) => {
            init_tracing(&cfg);
            install_service_with_engine_override(&cfg, upgrade, explicit_engine)?;
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
                        let configured = configured_engine_for_display(
                            explicit_config_path.as_deref(),
                            cfg.engine,
                            status.configured_engine,
                        );
                        println!("Engine: {} (configured)", configured.as_str());
                    }
                    Ok(())
                }
            }
        }
        Some(Command::Dns { addr }) => {
            init_tracing(&cfg);
            match addr {
                Some(target) => {
                    let validated = resolve_dns_target(&target)?;
                    vdpi::service::set_service_dns(&validated, &cfg)
                }
                None => {
                    let current = configured_dns_for_display(
                        explicit_config_path.as_deref(),
                        &cfg.dns_addr,
                    );
                    println!("DNS: {}", launcher::format_dns_label(&current));
                    Ok(())
                }
            }
        }
        Some(Command::Dashboard) => handle_dashboard_command(&cfg),
        Some(Command::Split { .. }) => unreachable!("handled by split command"),
        Some(Command::Status { .. }) | Some(Command::Doctor) | Some(Command::Update { .. }) => {
            init_tracing(&cfg);
            let rt = build_cli_runtime()?;
            rt.block_on(async move {
                match command {
                    Some(Command::Status { json }) => {
                        print_status_with_options_and_config(
                            &cfg,
                            json,
                            explicit_config_path.as_deref(),
                        )
                        .await
                    }
                    Some(Command::Doctor) => run_doctor(cfg).await,
                    Some(Command::Update { check, force }) => {
                        vdpi::update::run_update(check, force, &cfg).await
                    }
                    _ => unreachable!(),
                }
            })
        }
        Some(Command::Start) | None => {
            #[cfg(target_os = "windows")]
            if cfg.engine == EngineMode::Tun {
                if let Err(msg) = preflight_windows_wintun_dll() {
                    let _ = vdpi::platform::windows_tun::cleanup_orphan_wintun_adapter();
                    return Err(desktop_tun::format_tun_start_error(anyhow::anyhow!(
                        "{msg}"
                    )));
                }
            }
            #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
            if cfg.engine == EngineMode::Tun
                && !is_process_elevated()
                && !unattended
                && !is_service_mode(&cfg)
                && try_auto_elevate_current_cli("run vdpi in TUN mode")?
            {
                return Ok(());
            }
            #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
            let _ = unattended;
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

#[cfg(any(not(any(target_os = "android", target_os = "ios")), test))]
fn format_localized_split_summary(split: &SplitTunnelConfig) -> String {
    match launcher::active_lang() {
        vdpi::i18n::Lang::En => split.summary_label(),
        vdpi::i18n::Lang::Tr => {
            let count = split.apps.len();
            match split.mode {
                SplitTunnelMode::All => "Tüm uygulamalar".to_string(),
                SplitTunnelMode::Exclude => format!("Hariç tut ({count} uygulama)"),
                SplitTunnelMode::Include => format!("Dahil et ({count} uygulama)"),
            }
        }
    }
}

#[cfg(any(not(any(target_os = "android", target_os = "ios")), test))]
fn format_split_tunnel_saved_notice(split: &SplitTunnelConfig, service_restarted: bool) -> String {
    let summary = format_localized_split_summary(split);
    match (launcher::active_lang(), service_restarted) {
        (vdpi::i18n::Lang::En, true) => {
            format!("Split tunneling saved: {summary} (service restarted)")
        }
        (vdpi::i18n::Lang::En, false) => format!("Split tunneling saved: {summary}"),
        (vdpi::i18n::Lang::Tr, true) => {
            format!("Bölünmüş tünel kaydedildi: {summary} (servis yeniden başlatıldı)")
        }
        (vdpi::i18n::Lang::Tr, false) => format!("Bölünmüş tünel kaydedildi: {summary}"),
    }
}

#[cfg(any(target_os = "windows", test))]
fn format_wintun_preflight_notice(err_chain: &str) -> String {
    let lower = err_chain.to_ascii_lowercase();
    if lower.contains("sha-256")
        || lower.contains("hash")
        || lower.contains("mismatch")
        || lower.contains("verification failed")
        || lower.contains("corrupt")
    {
        launcher::tr(
            "wintun.dll is corrupted or mismatched - extract all files from the zip (keep wintun.dll beside vdpi.exe)",
            "wintun.dll bozuk veya eşleşmiyor - zip içindeki tüm dosyaları çıkarın (wintun.dll, vdpi.exe yanında olmalı)",
        )
        .to_string()
    } else {
        launcher::tr(
            "wintun.dll not found next to vdpi.exe - extract all files from the zip",
            "vdpi.exe yanında wintun.dll bulunamadı - zip içindeki tüm dosyaları çıkarın",
        )
        .to_string()
    }
}

#[cfg(target_os = "windows")]
fn preflight_windows_wintun_dll() -> std::result::Result<(), String> {
    match vdpi::platform::windows_tun::find_verified_wintun_dll() {
        Ok(_) => Ok(()),
        Err(err) => Err(format_wintun_preflight_notice(&format!("{err:#}"))),
    }
}

fn has_installed_system_service() -> bool {
    #[cfg(target_os = "windows")]
    {
        vdpi::platform::windows_service::query_windows_service_status().installed
    }
    #[cfg(target_os = "macos")]
    {
        Path::new(vdpi::service::LAUNCH_DAEMON_PLIST_PATH).exists()
    }
    #[cfg(target_os = "linux")]
    {
        Path::new(vdpi::service::SYSTEMD_SYSTEM_UNIT_PATH).exists()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

fn resolve_config_path_for_display(explicit: Option<&Path>, service_mode: bool) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    if service_mode || has_installed_system_service() {
        #[cfg(target_os = "windows")]
        {
            return system_config_path();
        }
        #[cfg(not(target_os = "windows"))]
        {
            let sys = system_config_path();
            if sys.is_file() || has_installed_system_service() {
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

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
fn try_auto_elevate_current_cli(action_description: &str) -> Result<bool> {
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Ok(false);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(target_os = "windows")]
    {
        let _ = action_description;
        vdpi::platform::windows_service::relaunch_elevated_and_wait(&args)?;
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        vdpi::service::relaunch_unix_sudo_and_wait(&args, action_description)?;
    }
    Ok(true)
}

#[cfg_attr(
    not(any(target_os = "windows", target_os = "macos", target_os = "linux")),
    allow(dead_code)
)]
enum WritableConfigPath {
    Ready(PathBuf),
    ElevatedAndDone,
}

fn resolve_writable_config_path(
    explicit: Option<&Path>,
    service_mode: bool,
) -> Result<WritableConfigPath> {
    if let Some(path) = explicit {
        return Ok(WritableConfigPath::Ready(path.to_path_buf()));
    }
    if service_mode {
        return Ok(WritableConfigPath::Ready(system_config_path()));
    }
    let sys = system_config_path();
    if has_installed_system_service() {
        if is_process_elevated() {
            return Ok(WritableConfigPath::Ready(sys));
        }
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        if try_auto_elevate_current_cli("update system vdpi configuration")? {
            return Ok(WritableConfigPath::ElevatedAndDone);
        }
        #[cfg(target_os = "windows")]
        let hint = "Run this command from an elevated Administrator terminal to update the system config, or pass `--config <path>` to edit a separate file.";
        #[cfg(not(target_os = "windows"))]
        let hint = "Re-run with `sudo` to update the system config, or pass `--config <path>` to edit a separate file.";
        anyhow::bail!(
            "system service is installed and uses {} which requires elevated privileges to modify. {hint}",
            sys.display()
        );
    }
    let usr = user_config_path();
    if usr.is_file() {
        return Ok(WritableConfigPath::Ready(usr));
    }
    if sys.is_file() {
        if is_process_elevated() {
            return Ok(WritableConfigPath::Ready(sys));
        }
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        if try_auto_elevate_current_cli("update system vdpi configuration")? {
            return Ok(WritableConfigPath::ElevatedAndDone);
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
    Ok(WritableConfigPath::Ready(usr))
}

fn resolve_i18n_language_pref(
    file_cfg: &FileConfig,
    explicit_config: bool,
) -> Option<Option<vdpi::i18n::Lang>> {
    if let Some(ref raw) = file_cfg.language {
        if raw.trim().eq_ignore_ascii_case("auto") {
            Some(None)
        } else {
            vdpi::i18n::Lang::parse(raw).map(Some)
        }
    } else if explicit_config {
        Some(None)
    } else {
        None
    }
}

fn resolve_startup_i18n_language_pref(
    file_cfg: &FileConfig,
    user_file_cfg: Option<&FileConfig>,
    explicit_config: bool,
) -> Option<Option<vdpi::i18n::Lang>> {
    if !explicit_config {
        if let Some(user_cfg) = user_file_cfg {
            if let Some(pref) = resolve_i18n_language_pref(user_cfg, false) {
                return Some(pref);
            }
        }
    }
    resolve_i18n_language_pref(file_cfg, explicit_config)
}

fn seed_i18n_language_pref(
    file_cfg: &FileConfig,
    user_file_cfg: Option<&FileConfig>,
    explicit_config: bool,
) {
    if let Some(pref) =
        resolve_startup_i18n_language_pref(file_cfg, user_file_cfg, explicit_config)
    {
        vdpi::i18n::set_language_pref(pref);
    }
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
        language: None,
    }
}

fn resolve_effective_config_key(
    cli: CliArgs,
    file_cfg: &FileConfig,
    raw_args: &[String],
    key: &str,
) -> Result<Option<String>> {
    let mut effective = runtime_to_file_config(&cli.resolve_runtime_config(file_cfg, raw_args));
    if let Some(ver) = file_cfg.schema_version {
        effective.schema_version = Some(ver);
    }
    if let Some(lang) = file_cfg.language.clone() {
        effective.language = Some(lang);
    }
    get_config_key(&effective, key)
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ElevatedUserInfo {
    uid: u32,
    gid: u32,
    home_dir: PathBuf,
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn parse_nonzero_unix_id(raw: Option<&str>) -> Option<u32> {
    raw.map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&id| id != 0)
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn sanitize_unix_username(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim)
        .filter(|s| !s.is_empty() && *s != "root" && !s.contains('/') && !s.contains('\0'))
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn resolve_elevated_invoking_user_with<FByUid, FByName>(
    sudo_uid: Option<&str>,
    sudo_user: Option<&str>,
    pkexec_uid: Option<&str>,
    doas_user: Option<&str>,
    real_uid: u32,
    lookup_by_uid: FByUid,
    lookup_by_name: FByName,
) -> Option<ElevatedUserInfo>
where
    FByUid: Fn(u32) -> Option<ElevatedUserInfo>,
    FByName: Fn(&str) -> Option<ElevatedUserInfo>,
{
    if let Some(uid) = parse_nonzero_unix_id(sudo_uid) {
        if let Some(user) = lookup_by_uid(uid).filter(|u| u.uid != 0) {
            return Some(user);
        }
    }
    if let Some(user_name) = sanitize_unix_username(sudo_user) {
        if let Some(user) = lookup_by_name(user_name).filter(|u| u.uid != 0) {
            return Some(user);
        }
    }
    if let Some(uid) = parse_nonzero_unix_id(pkexec_uid) {
        if let Some(user) = lookup_by_uid(uid).filter(|u| u.uid != 0) {
            return Some(user);
        }
    }
    if let Some(user_name) = sanitize_unix_username(doas_user) {
        if let Some(user) = lookup_by_name(user_name).filter(|u| u.uid != 0) {
            return Some(user);
        }
    }
    // Fallback for macOS `osascript ... with administrator privileges` (and setuid
    // elevation paths) where euid == 0 and SUDO_*/PKEXEC_*/DOAS_* are absent while
    // `getuid()` still identifies the invoking non-root user.
    if real_uid != 0 {
        if let Some(user) = lookup_by_uid(real_uid).filter(|u| u.uid != 0) {
            return Some(user);
        }
    }
    None
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn lookup_unix_passwd_by_uid(uid: u32) -> Option<ElevatedUserInfo> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::zeroed();
    let mut buf = vec![0u8; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `pwd` and `buf` are valid writable buffers for `getpwuid_r`.
    let rc = unsafe {
        libc::getpwuid_r(
            uid as libc::uid_t,
            pwd.as_mut_ptr(),
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: `getpwuid_r` returned 0 with non-null `result` pointing to initialized `pwd`.
    let pwd = unsafe { pwd.assume_init() };
    if pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: `pw_dir` is a valid NUL-terminated C string inside `buf`.
    let dir_bytes = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_bytes();
    if dir_bytes.is_empty() {
        return None;
    }
    Some(ElevatedUserInfo {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home_dir: PathBuf::from(OsStr::from_bytes(dir_bytes)),
    })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn lookup_unix_passwd_by_name(name: &str) -> Option<ElevatedUserInfo> {
    use std::ffi::{CStr, CString, OsStr};
    use std::os::unix::ffi::OsStrExt;

    let c_name = CString::new(name).ok()?;
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::zeroed();
    let mut buf = vec![0u8; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `c_name` is NUL-terminated; `pwd` and `buf` are valid writable buffers.
    let rc = unsafe {
        libc::getpwnam_r(
            c_name.as_ptr(),
            pwd.as_mut_ptr(),
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: `getpwnam_r` returned 0 with non-null `result` pointing to initialized `pwd`.
    let pwd = unsafe { pwd.assume_init() };
    if pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: `pw_dir` is a valid NUL-terminated C string inside `buf`.
    let dir_bytes = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_bytes();
    if dir_bytes.is_empty() {
        return None;
    }
    Some(ElevatedUserInfo {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home_dir: PathBuf::from(OsStr::from_bytes(dir_bytes)),
    })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn resolve_elevated_invoking_user() -> Option<ElevatedUserInfo> {
    // SAFETY: `geteuid(2)` is always safe to call and never fails.
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let sudo_uid = std::env::var("SUDO_UID").ok();
    let sudo_user = std::env::var("SUDO_USER").ok();
    let pkexec_uid = std::env::var("PKEXEC_UID").ok();
    let doas_user = std::env::var("DOAS_USER").ok();
    // SAFETY: `getuid(2)` is always safe to call and never fails.
    let real_uid = unsafe { libc::getuid() };
    resolve_elevated_invoking_user_with(
        sudo_uid.as_deref(),
        sudo_user.as_deref(),
        pkexec_uid.as_deref(),
        doas_user.as_deref(),
        real_uid,
        lookup_unix_passwd_by_uid,
        lookup_unix_passwd_by_name,
    )
}

/// Refuses to create directories, write files, or `lchown` through any symlink
/// (or `..` traversal) located beneath the invoking non-root user's home directory
/// while running as `root` under `sudo`, `pkexec`, or `doas`.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn verify_no_symlink_under_home(path: &Path, home_dir: &Path) -> Result<()> {
    use std::path::Component;

    let Ok(rel) = path.strip_prefix(home_dir) else {
        return Ok(());
    };
    for comp in rel.components() {
        if matches!(comp, Component::ParentDir) {
            anyhow::bail!(
                "refusing to traverse parent component '..' under user home '{}' while running as root",
                home_dir.display()
            );
        }
    }
    let mut cur = home_dir.to_path_buf();
    for comp in rel.components() {
        match comp {
            Component::CurDir => continue,
            Component::ParentDir => unreachable!("ParentDir checked above"),
            _ => cur.push(comp),
        }
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => {
                anyhow::bail!(
                    "refusing to write or chown through symlink '{}' under user home while running as root",
                    cur.display()
                );
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
            Err(err) => {
                return Err(anyhow::Error::new(err)
                    .context(format!("failed to inspect path {}", cur.display())));
            }
        }
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn collect_missing_dirs_under_home(dir: &Path, home_dir: &Path) -> Vec<PathBuf> {
    if !dir.starts_with(home_dir) {
        return Vec::new();
    }
    let mut missing = Vec::new();
    let mut cur = dir.to_path_buf();
    while cur != home_dir && cur.starts_with(home_dir) {
        if std::fs::symlink_metadata(&cur).is_err() {
            missing.push(cur.clone());
        }
        let Some(parent) = cur.parent() else {
            break;
        };
        cur = parent.to_path_buf();
    }
    missing.reverse();
    missing
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn absolutize_config_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.join(path)
    } else {
        path.to_path_buf()
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn is_safe_chown_target_under_home(target: &Path, home_dir: &Path) -> bool {
    use std::path::Component;

    if !home_dir.is_absolute()
        || home_dir.parent().is_none()
        || home_dir
            .components()
            .any(|comp| matches!(comp, Component::ParentDir))
    {
        return false;
    }
    if !target.starts_with(home_dir) {
        return false;
    }
    let Ok(rel) = target.strip_prefix(home_dir) else {
        return false;
    };
    if !rel
        .components()
        .any(|comp| !matches!(comp, Component::CurDir))
    {
        return false;
    }
    verify_no_symlink_under_home(target, home_dir).is_ok()
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn collect_chown_targets_under_home(
    abs_path: &Path,
    created_dirs: &[PathBuf],
    user_cfg_path: &Path,
    home_dir: &Path,
) -> Vec<PathBuf> {
    if !is_safe_chown_target_under_home(abs_path, home_dir) {
        return Vec::new();
    }

    let mut targets = Vec::new();
    let mut push_unique = |candidate: PathBuf| {
        if is_safe_chown_target_under_home(&candidate, home_dir) && !targets.contains(&candidate) {
            targets.push(candidate);
        }
    };

    for dir in created_dirs {
        push_unique(dir.clone());
    }

    if abs_path == user_cfg_path {
        if let Some(parent) = abs_path.parent() {
            if parent.starts_with(home_dir) {
                let mut ancestors = Vec::new();
                let mut cur = parent.to_path_buf();
                while cur != home_dir && cur.starts_with(home_dir) {
                    ancestors.push(cur.clone());
                    let Some(next) = cur.parent() else {
                        break;
                    };
                    cur = next.to_path_buf();
                }
                ancestors.reverse();
                for dir in ancestors {
                    push_unique(dir);
                }
            }
        }
    }

    push_unique(abs_path.to_path_buf());
    targets
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn chown_user_config_if_sudo_with_created(path: &Path, created_dirs: &[PathBuf]) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    if path == system_config_path() {
        return;
    }
    let Some(user) = resolve_elevated_invoking_user() else {
        return;
    };
    let abs_path = absolutize_config_path(path);
    if !abs_path.starts_with(&user.home_dir)
        || verify_no_symlink_under_home(&abs_path, &user.home_dir).is_err()
    {
        return;
    }
    let targets = collect_chown_targets_under_home(
        &abs_path,
        created_dirs,
        &user_config_path(),
        &user.home_dir,
    );
    if targets.is_empty() {
        return;
    }

    let uid = user.uid as libc::uid_t;
    let gid = user.gid as libc::gid_t;
    let chown_path = |target: &Path| {
        if !is_safe_chown_target_under_home(target, &user.home_dir) {
            return;
        }
        if let Ok(meta) = std::fs::symlink_metadata(target) {
            if meta.file_type().is_symlink() {
                return;
            }
        }
        if let Ok(c_path) = CString::new(target.as_os_str().as_bytes()) {
            // SAFETY: `c_path` is a valid NUL-terminated path string; `lchown` avoids following symlinks.
            let _ = unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };
        }
    };

    for target in targets {
        chown_path(&target);
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn chown_user_config_if_sudo(path: &Path) {
    let _ = path;
}

fn save_config_with_ownership(path: &Path, cfg: &FileConfig) -> Result<()> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let created_dirs = {
        if path != system_config_path() {
            if let Some(user) = resolve_elevated_invoking_user() {
                let abs_path = absolutize_config_path(path);
                verify_no_symlink_under_home(&abs_path, &user.home_dir)?;
                abs_path
                    .parent()
                    .map(|parent| collect_missing_dirs_under_home(parent, &user.home_dir))
                    .unwrap_or_default()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    };

    save_file_config_atomic(path, cfg)?;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    chown_user_config_if_sudo_with_created(path, &created_dirs);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    chown_user_config_if_sudo(path);

    Ok(())
}

const MAX_APPLY_CONFIG_FILE_BYTES: u64 = 1024 * 1024;
const MAX_DOMAIN_ENTRIES: usize = 512;

/// Exit code used by `vdpi config apply-file --restart` when `config.toml` was
/// saved successfully but pausing/resuming the running service failed.
const EXIT_CODE_APPLY_RESTART_FAILED: i32 = 2;

#[derive(Debug)]
struct ApplyFileRestartError {
    target: PathBuf,
    source: anyhow::Error,
}

impl std::fmt::Display for ApplyFileRestartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "applied configuration to {}, but failed to restart vdpi service",
            self.target.display()
        )
    }
}

impl std::error::Error for ApplyFileRestartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[cfg(windows)]
const WIN_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
#[cfg(windows)]
const WIN_FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

fn verify_no_symlink_or_reparse_ancestors(path: &Path) -> Result<()> {
    use anyhow::Context as _;
    use std::path::Component;

    let abs_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to resolve current working directory for config file path")?
            .join(path)
    };

    let mut cur = PathBuf::new();
    let mut has_normal_component = false;
    for comp in abs_path.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => {
                cur.push(comp.as_os_str());
                continue;
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                anyhow::bail!(
                    "refusing to traverse parent component '..' in config file path {}",
                    path.display()
                );
            }
            Component::Normal(part) => {
                has_normal_component = true;
                cur.push(part);
            }
        }

        let meta = std::fs::symlink_metadata(&cur).with_context(|| {
            format!("failed to inspect config path component {}", cur.display())
        })?;
        if meta.file_type().is_symlink() {
            #[cfg(target_os = "macos")]
            {
                use std::os::unix::fs::MetadataExt as _;
                let is_macos_system_link =
                    meta.uid() == 0 && matches!(cur.to_str(), Some("/var" | "/tmp" | "/etc"));
                if is_macos_system_link {
                    continue;
                }
            }
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::MetadataExt as _;
                let is_linux_ostree_link = meta.uid() == 0
                    && matches!(
                        cur.to_str(),
                        Some("/home" | "/usr/local" | "/var" | "/tmp" | "/etc")
                    );
                if is_linux_ostree_link {
                    continue;
                }
            }
            anyhow::bail!(
                "refusing to apply config file through symlink {}",
                cur.display()
            );
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt as _;
            if (meta.file_attributes() & WIN_FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                anyhow::bail!(
                    "refusing to apply config file through reparse point {}",
                    cur.display()
                );
            }
        }
    }

    if !has_normal_component {
        anyhow::bail!("config file path is not a regular file: {}", path.display());
    }
    Ok(())
}

#[cfg(any(unix, test))]
fn is_allowed_apply_file_owner(
    file_uid: u32,
    current_euid: u32,
    invoking_uid: Option<u32>,
) -> bool {
    if file_uid == current_euid {
        return true;
    }
    if current_euid == 0 {
        if let Some(uid) = invoking_uid {
            return file_uid == uid;
        }
    }
    false
}

/// Safely reads a bounded (`<= 1 MiB`) non-symlink, non-reparse-point regular
/// TOML file, parses it via [`vdpi::config_file::parse_config_toml`], and
/// validates DNS, split-tunnel apps, `chunk_size`, and [`BypassPolicy`].
fn load_and_validate_apply_config_file(path: &Path) -> Result<FileConfig> {
    use anyhow::Context as _;
    use std::io::Read as _;

    verify_no_symlink_or_reparse_ancestors(path)?;

    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect config file {}", path.display()))?;
    if meta.file_type().is_symlink() {
        anyhow::bail!("refusing to apply symlink config file {}", path.display());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if (meta.file_attributes() & WIN_FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            anyhow::bail!(
                "refusing to apply reparse-point config file {}",
                path.display()
            );
        }
    }
    if !meta.file_type().is_file() {
        anyhow::bail!("config file path is not a regular file: {}", path.display());
    }
    if meta.len() > MAX_APPLY_CONFIG_FILE_BYTES {
        anyhow::bail!(
            "config file {} exceeds maximum allowed size of {} bytes",
            path.display(),
            MAX_APPLY_CONFIG_FILE_BYTES
        );
    }

    let mut open_opts = std::fs::OpenOptions::new();
    open_opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        open_opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        open_opts.custom_flags(WIN_FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = open_opts
        .open(path)
        .with_context(|| format!("failed to open config file {}", path.display()))?;

    let opened_meta = file
        .metadata()
        .with_context(|| format!("failed to stat opened config file {}", path.display()))?;
    if opened_meta.file_type().is_symlink() {
        anyhow::bail!("refusing to apply symlink config file {}", path.display());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if (opened_meta.file_attributes() & WIN_FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            anyhow::bail!(
                "refusing to apply reparse-point config file {}",
                path.display()
            );
        }
    }
    if !opened_meta.file_type().is_file() {
        anyhow::bail!("config file path is not a regular file: {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let file_uid = opened_meta.uid();
        // SAFETY: `geteuid(2)` and `getuid(2)` are always safe to call and never fail.
        let current_euid = unsafe { libc::geteuid() } as u32;
        let current_ruid = unsafe { libc::getuid() } as u32;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        let invoking_uid = resolve_elevated_invoking_user()
            .map(|u| u.uid)
            .or_else(|| (current_ruid != 0 && current_ruid != current_euid).then_some(current_ruid));
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let invoking_uid = (current_ruid != 0 && current_ruid != current_euid).then_some(current_ruid);
        if !is_allowed_apply_file_owner(file_uid, current_euid, invoking_uid) {
            anyhow::bail!(
                "refusing to apply config file {} owned by unexpected uid {file_uid}",
                path.display()
            );
        }
        if current_euid == 0 && (opened_meta.mode() & 0o022) != 0 {
            anyhow::bail!(
                "refusing to apply group- or world-writable config file {} (mode {:04o})",
                path.display(),
                opened_meta.mode() & 0o7777
            );
        }
    }

    let mut buf = Vec::new();
    file.take(MAX_APPLY_CONFIG_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    if (buf.len() as u64) > MAX_APPLY_CONFIG_FILE_BYTES {
        anyhow::bail!(
            "config file {} exceeds maximum allowed size of {} bytes",
            path.display(),
            MAX_APPLY_CONFIG_FILE_BYTES
        );
    }

    let contents = String::from_utf8(buf)
        .with_context(|| format!("config file {} is not valid UTF-8", path.display()))?;
    let mut file_cfg = vdpi::config_file::parse_config_toml(&contents)
        .with_context(|| format!("failed to parse config file {}", path.display()))?;
    validate_applied_file_config(&mut file_cfg)?;
    Ok(file_cfg)
}

fn validate_applied_file_config(file_cfg: &mut FileConfig) -> Result<()> {
    file_cfg.schema_version.get_or_insert(CONFIG_SCHEMA_VERSION);
    if file_cfg.chunk_size == Some(0) {
        anyhow::bail!("chunk_size must be at least 1");
    }
    if let Some(ref raw_dns) = file_cfg.dns_addr {
        let validated = vdpi_core::dns::validate_custom_dns_input(raw_dns).map_err(|err| {
            let redacted = vdpi_core::dns::redact_dns_for_display(raw_dns);
            anyhow::anyhow!("invalid DNS server '{redacted}': {err}")
        })?;
        file_cfg.dns_addr = Some(validated);
    }
    if let Some(ref apps) = file_cfg.split_tunnel_apps {
        let validated_apps = vdpi::config_file::validate_split_tunnel_apps(apps)?;
        file_cfg.split_tunnel_apps = Some(validated_apps);
    }
    let bypass_domains = file_cfg.bypass_domains.as_deref().unwrap_or(&[]);
    if bypass_domains.len() > MAX_DOMAIN_ENTRIES {
        anyhow::bail!(
            "bypass_domains exceeds maximum of {MAX_DOMAIN_ENTRIES} entries (got {})",
            bypass_domains.len()
        );
    }
    let include_domains = file_cfg.include_domains.as_deref().unwrap_or(&[]);
    if include_domains.len() > MAX_DOMAIN_ENTRIES {
        anyhow::bail!(
            "include_domains exceeds maximum of {MAX_DOMAIN_ENTRIES} entries (got {})",
            include_domains.len()
        );
    }
    let _ = BypassPolicy::new(bypass_domains, include_domains)?;
    Ok(())
}

fn select_apply_file_target_path(
    explicit: Option<&Path>,
    service_mode: bool,
    service_state: ServiceState,
    system_service_installed: bool,
    elevated: bool,
    system_path: &Path,
    user_path: &Path,
) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if service_mode {
        return Ok(system_path.to_path_buf());
    }
    if system_service_installed {
        if elevated {
            return Ok(system_path.to_path_buf());
        }
        #[cfg(target_os = "windows")]
        let hint = "Run this command from an elevated Administrator terminal to update the system config, or pass `--config <path>` to target a separate file.";
        #[cfg(not(target_os = "windows"))]
        let hint = "Re-run with `sudo` to update the system config, or pass `--config <path>` to target a separate file.";
        anyhow::bail!(
            "system service is installed and uses {} which requires elevated privileges to modify. {hint}",
            system_path.display()
        );
    }
    if service_state != ServiceState::NotInstalled
        && elevated
        && !user_path.is_file()
        && system_path.is_file()
    {
        return Ok(system_path.to_path_buf());
    }
    Ok(user_path.to_path_buf())
}

#[allow(clippy::too_many_arguments)]
fn apply_config_file_with<FSave, FRestart>(
    source_path: &Path,
    restart: bool,
    explicit_path: Option<&Path>,
    service_mode: bool,
    service_state: ServiceState,
    system_service_installed: bool,
    elevated: bool,
    system_path: &Path,
    user_path: &Path,
    save_fn: FSave,
    restart_fn: FRestart,
) -> Result<(PathBuf, bool)>
where
    FSave: FnOnce(&Path, &FileConfig) -> Result<()>,
    FRestart: FnOnce() -> Result<()>,
{
    let file_cfg = load_and_validate_apply_config_file(source_path)?;
    let target = select_apply_file_target_path(
        explicit_path,
        service_mode,
        service_state,
        system_service_installed,
        elevated,
        system_path,
        user_path,
    )?;
    save_fn(&target, &file_cfg)?;

    let targets_active_config =
        explicit_path.is_none() || target == system_path || target == user_path;
    let restarted = if restart && targets_active_config && service_state == ServiceState::Running {
        if let Err(source) = restart_fn() {
            return Err(anyhow::Error::new(ApplyFileRestartError { target, source }));
        }
        true
    } else {
        false
    };
    Ok((target, restarted))
}

/// Applies a validated TOML configuration file atomically to the active
/// `config.toml` target without placing sensitive DoH URLs on process argv, and
/// optionally restarts a running OS service so changes take effect immediately.
fn handle_config_apply_file(
    source_path: &Path,
    restart: bool,
    explicit_path: Option<&Path>,
    service_mode: bool,
) -> Result<()> {
    use anyhow::Context as _;

    let service_state = vdpi::service::detect_service_state();
    let system_service_installed = has_installed_system_service();
    let elevated = is_process_elevated();

    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    if explicit_path.is_none() && !service_mode && system_service_installed && !elevated {
        // Validate before triggering an interactive elevation prompt.
        let _ = load_and_validate_apply_config_file(source_path)?;
        if try_auto_elevate_current_cli("update system vdpi configuration")? {
            return Ok(());
        }
    }

    let system_path = system_config_path();
    let user_path = user_config_path();
    let (target, restarted) = apply_config_file_with(
        source_path,
        restart,
        explicit_path,
        service_mode,
        service_state,
        system_service_installed,
        elevated,
        &system_path,
        &user_path,
        save_config_with_ownership,
        || {
            vdpi::service::pause_service_quiet()
                .context("failed to pause running vdpi service for restart")?;
            vdpi::service::resume_service_quiet()
                .context("failed to resume vdpi service after pause")
        },
    )?;

    if restarted {
        println!(
            "Applied configuration to {} and restarted vdpi service.",
            target.display()
        );
    } else {
        println!("Applied configuration to {}", target.display());
        if !restart {
            maybe_print_service_restart_note(explicit_path, &target);
        }
    }
    Ok(())
}

fn maybe_print_service_restart_note(explicit_path: Option<&Path>, target: &Path) {
    if explicit_path.is_some() && target != system_config_path() && target != user_config_path() {
        return;
    }
    if vdpi::service::detect_service_state() == ServiceState::Running {
        println!(
            "Note: vdpi background service is running; changes apply on next restart (`vdpi pause && vdpi resume`)."
        );
    }
}

fn build_config_show_file_config(cfg: &RuntimeConfig, file_cfg: &FileConfig) -> FileConfig {
    let mut show_cfg = runtime_to_file_config(cfg);
    show_cfg.language.clone_from(&file_cfg.language);
    show_cfg
}

fn build_config_show_json(
    loaded_path: Option<&Path>,
    cfg: &RuntimeConfig,
    file_cfg: &FileConfig,
) -> serde_json::Value {
    serde_json::json!({
        "config_path": loaded_path.map(|p| p.display().to_string()),
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
        "language": file_cfg.language,
    })
}

fn handle_config_command(
    action: Option<ConfigCommand>,
    cli: CliArgs,
    raw_args: &[String],
) -> Result<()> {
    let explicit_path = cli.config_path.clone();
    let service_mode = cli.service;
    let effective_service_mode =
        service_mode || (explicit_path.is_none() && has_installed_system_service());

    match action.unwrap_or(ConfigCommand::Show { json: false }) {
        ConfigCommand::Show { json } => {
            let (loaded_path, file_cfg) =
                load_file_config(explicit_path.as_deref(), effective_service_mode)?;
            let cfg = cli.resolve_runtime_config(&file_cfg, raw_args);
            if json {
                let payload = build_config_show_json(loaded_path.as_deref(), &cfg, &file_cfg);
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
                print!(
                    "{}",
                    render_config_toml(&build_config_show_file_config(&cfg, &file_cfg))
                );
            }
            Ok(())
        }
        ConfigCommand::Path => {
            let path = resolve_config_path_for_display(explicit_path.as_deref(), service_mode);
            println!("{}", path.display());
            Ok(())
        }
        ConfigCommand::Get { key } => {
            let (_, file_cfg) =
                load_file_config(explicit_path.as_deref(), effective_service_mode)?;
            if let Some(val) = resolve_effective_config_key(cli, &file_cfg, raw_args, &key)? {
                println!("{val}");
            }
            Ok(())
        }
        ConfigCommand::Set { key, value } => {
            let target = match resolve_writable_config_path(explicit_path.as_deref(), service_mode)?
            {
                WritableConfigPath::Ready(path) => path,
                WritableConfigPath::ElevatedAndDone => return Ok(()),
            };
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
            save_config_with_ownership(&target, &file_cfg)?;
            println!("Set {key} = {value} in {}", target.display());
            maybe_print_service_restart_note(explicit_path.as_deref(), &target);
            Ok(())
        }
        ConfigCommand::Unset { key } => {
            let target = match resolve_writable_config_path(explicit_path.as_deref(), service_mode)?
            {
                WritableConfigPath::Ready(path) => path,
                WritableConfigPath::ElevatedAndDone => return Ok(()),
            };
            let (loaded_path, mut file_cfg) =
                load_file_config_or_default(Some(&target), service_mode)?;
            unset_config_key(&mut file_cfg, &key)?;
            if loaded_path.is_none() {
                println!("No config file at {}; nothing to unset.", target.display());
                return Ok(());
            }
            save_config_with_ownership(&target, &file_cfg)?;
            println!("Unset {key} in {}", target.display());
            maybe_print_service_restart_note(explicit_path.as_deref(), &target);
            Ok(())
        }
        ConfigCommand::Validate => {
            let (loaded_path, file_cfg) =
                load_file_config(explicit_path.as_deref(), effective_service_mode)?;
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
            let target = match resolve_writable_config_path(explicit_path.as_deref(), service_mode)?
            {
                WritableConfigPath::Ready(path) => path,
                WritableConfigPath::ElevatedAndDone => return Ok(()),
            };
            let fresh = FileConfig {
                schema_version: Some(CONFIG_SCHEMA_VERSION),
                ..Default::default()
            };
            save_config_with_ownership(&target, &fresh)?;
            println!("Reset configuration to defaults: {}", target.display());
            maybe_print_service_restart_note(explicit_path.as_deref(), &target);
            Ok(())
        }
        ConfigCommand::ApplyFile { path, restart } => {
            handle_config_apply_file(&path, restart, explicit_path.as_deref(), service_mode)
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
    let dns_addr = live
        .dns_addr
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| vdpi::service::load_configured_dns(&fallback_cfg.dns_addr));
    tui_dashboard::DashboardInfo {
        engine: dashboard_engine_from_live(live, fallback_cfg.system_proxy),
        mode: parse_live_desync_mode(live.mode.as_deref(), fallback_cfg.mode),
        enable_doh: live.doh.unwrap_or(fallback_cfg.enable_doh),
        dns_addr: Some(dns_addr),
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn attached_telemetry_from_live(
    live: &vdpi::service::LiveEngineStatus,
    fallback_cfg: &RuntimeConfig,
) -> tui_dashboard::AttachedTelemetry {
    let dns_addr = live
        .dns_addr
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| vdpi::service::load_configured_dns(&fallback_cfg.dns_addr));
    tui_dashboard::AttachedTelemetry {
        snap: telemetry_snapshot_from_live(live),
        engine: dashboard_engine_from_live(live, fallback_cfg.system_proxy),
        mode: parse_live_desync_mode(live.mode.as_deref(), fallback_cfg.mode),
        doh: live.doh.unwrap_or(fallback_cfg.enable_doh),
        dns_addr: Some(dns_addr),
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
        use std::io::IsTerminal;

        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            anyhow::bail!(
                "live dashboard requires an interactive terminal (use 'vdpi status' for non-interactive output)"
            );
        }
        let Some(live) = probe_live_engine_for_dashboard(cfg) else {
            anyhow::bail!("No running vdpi service detected. Run 'vdpi' or 'vdpi start' first.");
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

fn remove_split_tunnel_apps(
    existing: &[String],
    to_remove: &[String],
) -> Result<(Vec<String>, usize)> {
    let validated_remove = vdpi::config_file::validate_split_tunnel_apps(to_remove)?;
    if to_remove.iter().any(|raw| raw.trim().is_empty()) {
        anyhow::bail!("application name cannot be empty");
    }
    let remove_keys: std::collections::HashSet<String> = validated_remove
        .into_iter()
        .map(|cleaned| vdpi_core::config::normalize_split_app_name(&cleaned))
        .filter(|key| !key.is_empty())
        .collect();
    if remove_keys.is_empty() {
        anyhow::bail!("no valid application names provided");
    }
    let remaining: Vec<String> = existing
        .iter()
        .filter(|entry| {
            let entry_key =
                vdpi::config_file::sanitize_split_tunnel_apps(std::slice::from_ref(entry))
                    .into_iter()
                    .next()
                    .map(|cleaned| vdpi_core::config::normalize_split_app_name(&cleaned))
                    .unwrap_or_else(|| vdpi_core::config::normalize_split_app_name(entry));
            !remove_keys.contains(&entry_key)
        })
        .cloned()
        .collect();
    let removed = existing.len().saturating_sub(remaining.len());
    Ok((remaining, removed))
}

fn load_effective_split_tunnel_with_file_config(
    config_path: Option<&Path>,
    cli_split_mode: Option<SplitTunnelMode>,
    cli_split_apps: &[String],
    allow_missing_explicit: bool,
) -> Result<(SplitTunnelConfig, Option<FileConfig>)> {
    let (mut cfg, explicit_file_cfg) = if let Some(path) = config_path {
        let (_, file_cfg) = if allow_missing_explicit {
            load_file_config_or_default(Some(path), false)?
        } else {
            load_file_config(Some(path), false)?
        };
        let split_cfg = SplitTunnelConfig {
            mode: file_cfg.split_tunnel_mode.unwrap_or_default(),
            apps: file_cfg
                .split_tunnel_apps
                .as_deref()
                .map(vdpi::config_file::sanitize_split_tunnel_apps)
                .unwrap_or_default(),
        };
        (split_cfg, Some(file_cfg))
    } else {
        (vdpi::service::load_configured_split_tunnel(), None)
    };
    if let Some(mode) = cli_split_mode {
        cfg.mode = mode;
    }
    if !cli_split_apps.is_empty() {
        cfg.apps = vdpi::config_file::sanitize_split_tunnel_apps(cli_split_apps);
    }
    Ok((cfg, explicit_file_cfg))
}

fn load_effective_split_tunnel(
    config_path: Option<&Path>,
    cli_split_mode: Option<SplitTunnelMode>,
    cli_split_apps: &[String],
    allow_missing_explicit: bool,
) -> Result<SplitTunnelConfig> {
    load_effective_split_tunnel_with_file_config(
        config_path,
        cli_split_mode,
        cli_split_apps,
        allow_missing_explicit,
    )
    .map(|(cfg, _)| cfg)
}

fn save_split_tunnel_target(
    config_path: Option<&Path>,
    cfg: &SplitTunnelConfig,
) -> Result<String> {
    if let Some(path) = config_path {
        let validated_apps = vdpi::config_file::validate_split_tunnel_apps(&cfg.apps)?;
        let normalized = SplitTunnelConfig {
            mode: cfg.mode,
            apps: validated_apps,
        };
        let (_, mut file_cfg) = load_file_config_or_default(Some(path), false)?;
        file_cfg.schema_version.get_or_insert(CONFIG_SCHEMA_VERSION);
        file_cfg.split_tunnel_mode = Some(normalized.mode);
        file_cfg.split_tunnel_apps = Some(normalized.apps.clone());
        save_config_with_ownership(path, &file_cfg)?;
        Ok(format!(
            "Split tunneling saved: {} ({})",
            normalized.summary_label(),
            path.display()
        ))
    } else {
        vdpi::service::set_service_split_tunnel(cfg)
    }
}

fn handle_split_command(
    action: Option<SplitCommand>,
    config_path: Option<&Path>,
    cli_split_mode: Option<SplitTunnelMode>,
    cli_split_apps: &[String],
) -> Result<()> {
    match action {
        None => {
            #[cfg(any(target_os = "android", target_os = "ios"))]
            {
                let _ = (config_path, cli_split_mode, cli_split_apps);
                anyhow::bail!(
                    "interactive split-tunnel picker is not supported on {}",
                    platform_name()
                );
            }
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                use std::io::IsTerminal;

                if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
                    anyhow::bail!(
                        "interactive split-tunnel picker requires an interactive terminal (use 'vdpi split status|list|mode|add|remove|clear')"
                    );
                }
                let (current, explicit_file_cfg) = load_effective_split_tunnel_with_file_config(
                    config_path,
                    cli_split_mode,
                    cli_split_apps,
                    true,
                )?;
                if let Some(ref file_cfg) = explicit_file_cfg {
                    seed_i18n_language_pref(file_cfg, None, true);
                }
                if let Some(new_cfg) = vdpi::split_tunnel::tui::run_split_tunnel_picker(current)? {
                    let msg = save_split_tunnel_target(config_path, &new_cfg)?;
                    println!("{msg}");
                }
                Ok(())
            }
        }
        Some(SplitCommand::Status { json }) => {
            let current =
                load_effective_split_tunnel(config_path, cli_split_mode, cli_split_apps, false)?;
            if json {
                let payload = serde_json::json!({
                    "mode": current.mode.as_str(),
                    "apps": current.apps,
                    "summary": current.summary_label(),
                });
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else {
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
            }
            Ok(())
        }
        Some(SplitCommand::List { query, filter }) => {
            let query = query.or(filter);
            #[cfg(any(target_os = "android", target_os = "ios"))]
            {
                let _ = (query, config_path, cli_split_mode, cli_split_apps);
                anyhow::bail!(
                    "application discovery is not supported on {}",
                    platform_name()
                );
            }
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                let current = load_effective_split_tunnel(
                    config_path,
                    cli_split_mode,
                    cli_split_apps,
                    false,
                )?;
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
            let mut current =
                load_effective_split_tunnel(config_path, cli_split_mode, cli_split_apps, true)?;
            current.mode = mode;
            let msg = save_split_tunnel_target(config_path, &current)?;
            println!("{msg}");
            Ok(())
        }
        Some(SplitCommand::Add { apps }) => {
            let mut current =
                load_effective_split_tunnel(config_path, cli_split_mode, cli_split_apps, true)?;
            current.apps = merge_split_tunnel_apps(&current.apps, &apps)?;
            let msg = save_split_tunnel_target(config_path, &current)?;
            println!("{msg}");
            if current.mode == SplitTunnelMode::All {
                println!(
                    "Note: split tunneling mode is currently 'all'. Run 'vdpi split mode exclude' or 'vdpi split mode include' to activate."
                );
            }
            Ok(())
        }
        Some(SplitCommand::Remove { apps }) => {
            let mut current =
                load_effective_split_tunnel(config_path, cli_split_mode, cli_split_apps, true)?;
            let (remaining, removed) = remove_split_tunnel_apps(&current.apps, &apps)?;
            if removed == 0 {
                println!(
                    "No matching applications found in the configured split-tunnel list; no changes made."
                );
                return Ok(());
            }
            current.apps = remaining;
            let msg = save_split_tunnel_target(config_path, &current)?;
            println!("{msg}");
            Ok(())
        }
        Some(SplitCommand::Clear) => {
            let cleared = SplitTunnelConfig::default();
            let msg = save_split_tunnel_target(config_path, &cleared)?;
            println!("{msg}");
            Ok(())
        }
        Some(SplitCommand::Apply { mode, apps }) => {
            let new_cfg = SplitTunnelConfig { mode, apps };
            let msg = save_split_tunnel_target(config_path, &new_cfg)?;
            println!("{msg}");
            Ok(())
        }
    }
}

fn configured_engine_for_display(
    explicit_config_path: Option<&Path>,
    cfg_engine: EngineMode,
    probed_configured_engine: EngineMode,
) -> EngineMode {
    if explicit_config_path.is_some() {
        cfg_engine
    } else {
        probed_configured_engine
    }
}

fn configured_dns_for_display(explicit_config_path: Option<&Path>, cfg_dns_addr: &str) -> String {
    if explicit_config_path.is_some() {
        cfg_dns_addr.to_string()
    } else {
        vdpi::service::load_configured_dns(cfg_dns_addr)
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

fn resolve_dns_target(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!(
            "DNS server cannot be empty (enter a preset name, IPv4/IPv6 address, or https:// DoH URL)"
        );
    }
    let normalized_key: String = trimmed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    for preset in &launcher::DNS_PRESETS {
        let preset_key: String = preset
            .name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_lowercase())
            .collect();
        if normalized_key == preset_key || trimmed.eq_ignore_ascii_case(preset.addr) {
            return Ok(preset.addr.to_string());
        }
    }
    if normalized_key == "family" {
        return Ok("1.1.1.3".to_string());
    }
    vdpi_core::dns::validate_custom_dns_input(trimmed).map_err(|err| {
        let redacted = vdpi_core::dns::redact_dns_for_display(trimmed);
        anyhow::anyhow!("invalid DNS server '{redacted}': {err}")
    })
}

fn foreground_tokio_worker_threads() -> usize {
    std::thread::available_parallelism().map_or(2, |n| n.get().clamp(2, 4))
}

fn build_runtime() -> Result<tokio::runtime::Runtime> {
    // Cap foreground Tokio workers to 2..=4 instead of spawning 16-24 workers on
    // high-core desktops so foreground TUN traffic never preempts real-time audio
    // engines such as VoiceMeeter.
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(foreground_tokio_worker_threads())
        .max_blocking_threads(16)
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
const FOREGROUND_PROXY_VPN_POLL_INTERVAL: Duration = Duration::from_secs(3);

#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
const FOREGROUND_PROXY_VPN_RECOVERY_POLL_INTERVAL: Duration = Duration::from_secs(1);

#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
fn foreground_proxy_vpn_poll_interval(vpn_yielded: bool) -> Duration {
    if vpn_yielded {
        FOREGROUND_PROXY_VPN_RECOVERY_POLL_INTERVAL
    } else {
        FOREGROUND_PROXY_VPN_POLL_INTERVAL
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
    include_domains: Vec<String>,
    vpn_coexistence: vdpi::config::VpnCoexistence,
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
impl ForegroundProxySpec {
    fn from_runtime_config(
        cfg: &RuntimeConfig,
        primary_addr: std::net::SocketAddr,
        socks_addr: Option<std::net::SocketAddr>,
    ) -> Self {
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let _ = socks_addr;
        Self {
            proxy_addr: normalize_system_proxy_addr(primary_addr),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            socks_port: socks_addr
                .filter(|_| cfg.socks_system_proxy)
                .map(|a| a.port()),
            #[cfg(windows)]
            env_proxy: cfg.env_proxy,
            bypass_domains: cfg.bypass_domains.clone(),
            include_domains: cfg.patterns.clone(),
            vpn_coexistence: cfg.vpn_coexistence,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn to_unix_spec(&self) -> foreground::ForegroundProxySpec {
        foreground::ForegroundProxySpec {
            addr: self.proxy_addr,
            socks_port: self.socks_port,
            bypass: self.bypass_domains.clone(),
            include_domains: self.include_domains.clone(),
            vpn_coexistence: self.vpn_coexistence,
        }
    }

    fn activate(&self) -> Result<(foreground::ForegroundProxy, String)> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let session = foreground::ForegroundProxy::activate_spec(&self.to_unix_spec())?;
            let summary = session.summary.clone();
            Ok((session, summary))
        }
        #[cfg(windows)]
        {
            let _ = (&self.include_domains, self.vpn_coexistence);
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
            let spec = ForegroundProxySpec::from_runtime_config(&cfg, primary_addr, socks_addr);

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
                    #[cfg(windows)]
                    {
                        let _ = tokio::task::spawn_blocking(|| {
                            let _ = vdpi::platform::windows::clear_all_windows_proxies();
                            vdpi::platform::windows::flush_dns_resolver_cache();
                        })
                        .await;
                    }
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
            doh = vdpi_core::dns::is_effective_doh_target(&cfg.dns_addr, cfg.enable_doh),
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
        let sup_ctx = ctx.clone();
        let vpn_policy = cfg.vpn_coexistence;
        tokio::spawn(async move {
            if vpn_policy == VpnCoexistence::Off {
                let _ = sup_shutdown_rx.wait_for(|stopped| *stopped).await;
            } else {
                let mut last_resume_attempt: Option<Instant> = None;
                let mut last_activate_error: Option<(String, Instant)> = None;

                loop {
                    let poll_interval =
                        foreground_proxy_vpn_poll_interval(proxy_vpn_guard.is_yielded());
                    tokio::select! {
                        biased;
                        changed = sup_shutdown_rx.changed() => {
                            if changed.is_err() || *sup_shutdown_rx.borrow() {
                                break;
                            }
                        }
                        _ = tokio::time::sleep(poll_interval) => {
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
                                    sup_ctx.dns.clear_cache().await;
                                    #[cfg(windows)]
                                    let _ = tokio::task::spawn_blocking(
                                        vdpi::platform::windows::flush_dns_resolver_cache,
                                    )
                                    .await;
                                }
                                GuardAction::ResumeTun => {
                                    proxy_last_warned = None;
                                    sup_ctx.dns.clear_cache().await;
                                    #[cfg(windows)]
                                    let mut flushed_os_dns = false;
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
                                                    #[cfg(windows)]
                                                    {
                                                        let _ = tokio::task::spawn_blocking(
                                                            vdpi::platform::windows::flush_dns_resolver_cache,
                                                        )
                                                        .await;
                                                        flushed_os_dns = true;
                                                    }
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
                                    #[cfg(windows)]
                                    if !flushed_os_dns {
                                        let _ = tokio::task::spawn_blocking(
                                            vdpi::platform::windows::flush_dns_resolver_cache,
                                        )
                                        .await;
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
                                                    sup_ctx.dns.clear_cache().await;
                                                    #[cfg(windows)]
                                                    let _ = tokio::task::spawn_blocking(
                                                        vdpi::platform::windows::flush_dns_resolver_cache,
                                                    )
                                                    .await;
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
            enable_doh: vdpi_core::dns::is_effective_doh_target(&cfg.dns_addr, cfg.enable_doh),
            dns_addr: Some(cfg.dns_addr.clone()),
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
    pub(super) const TUN_RECONCILE_ACTIVE_INTERVAL: Duration = Duration::from_secs(3);
    pub(super) const TUN_RECONCILE_RECOVERY_INTERVAL: Duration = Duration::from_secs(1);
    const OFFLINE_STANDBY_RETRY_INTERVAL: Duration = Duration::from_secs(5);

    pub(super) fn tun_reconcile_interval(tun_running: bool, vpn_yielded: bool) -> Duration {
        if tun_running && !vpn_yielded {
            TUN_RECONCILE_ACTIVE_INTERVAL
        } else {
            TUN_RECONCILE_RECOVERY_INTERVAL
        }
    }

    pub(super) fn retry_backoff(failures: u32) -> Duration {
        let shift = failures.saturating_sub(1).min(4);
        let secs = 3u64.saturating_mul(1u64 << shift).min(30);
        Duration::from_secs(secs)
    }

    pub(super) fn is_transient_offline_tun_error(err: &anyhow::Error) -> bool {
        let lower = format!("{err:#}").to_ascii_lowercase();
        lower.contains("no active physical network uplink")
            || lower.contains("no physical default ipv4")
            || lower.contains("no non-tun ipv4 or ipv6 default route")
            || lower.contains("no active uplink")
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum TunStartErrorLogAction {
        LogOfflineStandby,
        SuppressOfflineStandby,
        LogRetryableError,
    }

    pub(super) fn classify_tun_start_error_log(
        offline_standby_logged: &mut bool,
        err: &anyhow::Error,
    ) -> TunStartErrorLogAction {
        if is_transient_offline_tun_error(err) {
            if *offline_standby_logged {
                TunStartErrorLogAction::SuppressOfflineStandby
            } else {
                *offline_standby_logged = true;
                TunStartErrorLogAction::LogOfflineStandby
            }
        } else {
            *offline_standby_logged = false;
            TunStartErrorLogAction::LogRetryableError
        }
    }

    #[cfg(target_os = "windows")]
    pub(super) mod windows_power {
        use std::ffi::c_void;
        use std::ptr;
        use std::sync::{Mutex, OnceLock};
        use tokio::sync::watch;
        use tracing::{info, warn};
        use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
        use windows_sys::Win32::System::LibraryLoader::{
            GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
        };

        pub(crate) const PBT_APMRESUMESUSPEND: u32 = 0x0000_0007;
        pub(crate) const PBT_APMRESUMEAUTOMATIC: u32 = 0x0000_0012;
        const DEVICE_NOTIFY_CALLBACK: u32 = 0x0000_0002;
        const NO_ERROR: u32 = 0;

        static POWER_RESUME_TX: OnceLock<Mutex<Option<watch::Sender<u64>>>> = OnceLock::new();

        pub(crate) fn should_trigger_power_resume_reconcile(event_type: u32) -> bool {
            event_type == PBT_APMRESUMEAUTOMATIC || event_type == PBT_APMRESUMESUSPEND
        }

        #[repr(C)]
        struct DeviceNotifySubscribeParameters {
            callback: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> u32,
            context: *mut c_void,
        }

        type PowerRegisterSuspendResumeNotificationFn = unsafe extern "system" fn(
            flags: u32,
            recipient: *mut c_void,
            registration_handle: *mut *mut c_void,
        ) -> u32;

        type PowerUnregisterSuspendResumeNotificationFn =
            unsafe extern "system" fn(registration_handle: *mut c_void) -> u32;

        unsafe extern "system" fn power_suspend_resume_callback(
            _context: *mut c_void,
            event_type: u32,
            _setting: *mut c_void,
        ) -> u32 {
            if should_trigger_power_resume_reconcile(event_type) {
                if let Some(lock) = POWER_RESUME_TX.get() {
                    if let Some(ref tx) = *lock.lock().unwrap_or_else(|e| e.into_inner()) {
                        tx.send_modify(|n| *n = n.wrapping_add(1));
                    }
                }
            }
            NO_ERROR
        }

        pub(super) struct SuspendResumeNotificationGuard {
            hmod: HMODULE,
            reg_handle: *mut c_void,
            unregister_fn: PowerUnregisterSuspendResumeNotificationFn,
        }

        // SAFETY: `HMODULE` and `HPOWERNOTIFY` are process-global Win32 handles that can be
        // unregistered and freed safely when the foreground TUN supervisor stops.
        unsafe impl Send for SuspendResumeNotificationGuard {}

        fn clear_power_resume_tx() {
            if let Some(lock) = POWER_RESUME_TX.get() {
                *lock.lock().unwrap_or_else(|e| e.into_inner()) = None;
            }
        }

        impl SuspendResumeNotificationGuard {
            pub(super) fn register(tx: watch::Sender<u64>) -> Option<Self> {
                {
                    let lock = POWER_RESUME_TX.get_or_init(|| Mutex::new(None));
                    *lock.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
                }

                let dll_wide: Vec<u16> = "powrprof.dll\0".encode_utf16().collect();
                let hmod = unsafe {
                    LoadLibraryExW(
                        dll_wide.as_ptr(),
                        ptr::null_mut(),
                        LOAD_LIBRARY_SEARCH_SYSTEM32,
                    )
                };
                if hmod.is_null() {
                    warn!("could not load powrprof.dll for Modern Standby wake notifications");
                    clear_power_resume_tx();
                    return None;
                }

                let register_proc = unsafe {
                    GetProcAddress(
                        hmod,
                        c"PowerRegisterSuspendResumeNotification"
                            .as_ptr()
                            .cast::<u8>(),
                    )
                };
                let unregister_proc = unsafe {
                    GetProcAddress(
                        hmod,
                        c"PowerUnregisterSuspendResumeNotification"
                            .as_ptr()
                            .cast::<u8>(),
                    )
                };
                let (Some(register_proc), Some(unregister_proc)) = (register_proc, unregister_proc)
                else {
                    warn!(
                        "powrprof.dll missing PowerRegisterSuspendResumeNotification exports"
                    );
                    unsafe {
                        let _ = FreeLibrary(hmod);
                    }
                    clear_power_resume_tx();
                    return None;
                };

                let register_fn: PowerRegisterSuspendResumeNotificationFn =
                    unsafe { std::mem::transmute_copy(&register_proc) };
                let unregister_fn: PowerUnregisterSuspendResumeNotificationFn =
                    unsafe { std::mem::transmute_copy(&unregister_proc) };

                let mut params = DeviceNotifySubscribeParameters {
                    callback: power_suspend_resume_callback,
                    context: ptr::null_mut(),
                };
                let mut reg_handle: *mut c_void = ptr::null_mut();
                let rc = unsafe {
                    register_fn(
                        DEVICE_NOTIFY_CALLBACK,
                        (&mut params as *mut DeviceNotifySubscribeParameters).cast::<c_void>(),
                        &mut reg_handle,
                    )
                };
                if rc != NO_ERROR || reg_handle.is_null() {
                    warn!(
                        error = rc,
                        "PowerRegisterSuspendResumeNotification failed for foreground TUN"
                    );
                    unsafe {
                        let _ = FreeLibrary(hmod);
                    }
                    clear_power_resume_tx();
                    return None;
                }

                info!("registered Modern Standby (S0ix) power suspend/resume notification");
                Some(Self {
                    hmod,
                    reg_handle,
                    unregister_fn,
                })
            }
        }

        impl Drop for SuspendResumeNotificationGuard {
            fn drop(&mut self) {
                let mut unregistered = true;
                if !self.reg_handle.is_null() {
                    let rc = unsafe { (self.unregister_fn)(self.reg_handle) };
                    if rc != NO_ERROR {
                        warn!(
                            error = rc,
                            "PowerUnregisterSuspendResumeNotification failed"
                        );
                        unregistered = false;
                    }
                    self.reg_handle = ptr::null_mut();
                }
                clear_power_resume_tx();
                if unregistered && !self.hmod.is_null() {
                    unsafe {
                        let _ = FreeLibrary(self.hmod);
                    }
                    self.hmod = ptr::null_mut();
                }
            }
        }
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
                    || lower.contains("mismatch")
                    || lower.contains("corrupt")
                    || lower.contains("loadlibrary")))
    }

    pub(super) fn effective_tun_dns_ipv4_only(
        explicit_dns_ipv4_only: bool,
        session_ipv6_active: bool,
    ) -> bool {
        explicit_dns_ipv4_only || !session_ipv6_active
    }

    pub(super) async fn sync_tun_dns_ipv4_only_if_changed<F, Fut>(
        dns: &vdpi::dns::DnsResolver,
        tun_running: bool,
        explicit_dns_ipv4_only: bool,
        tun_ipv6_active: bool,
        flush_os_cache: F,
    ) -> bool
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        if !tun_running {
            return false;
        }
        let next = effective_tun_dns_ipv4_only(explicit_dns_ipv4_only, tun_ipv6_active);
        let prev = dns.is_ipv4_only();
        if prev == next {
            return false;
        }
        dns.set_ipv4_only(next);
        dns.clear_cache().await;
        flush_os_cache().await;
        true
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

        fn is_ipv6_active(&self) -> bool {
            match self {
                #[cfg(target_os = "windows")]
                Self::Windows(s) => s.is_ipv6_active(),
                #[cfg(target_os = "macos")]
                Self::Macos(s) => s.is_ipv6_active(),
                #[cfg(target_os = "linux")]
                Self::Linux(s) => s.is_ipv6_active(),
                #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
                Self::Unsupported => false,
            }
        }
    }

    struct DesktopTunSlot {
        session: Option<PlatformTunHandle>,
        pipeline_stop_tx: Option<watch::Sender<bool>>,
        pipeline_task: Option<tokio::task::JoinHandle<Result<()>>>,
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        route_rx: Option<watch::Receiver<u64>>,
    }

    impl DesktopTunSlot {
        fn empty() -> Self {
            Self {
                session: None,
                pipeline_stop_tx: None,
                pipeline_task: None,
                #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
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

        fn is_ipv6_active(&self) -> bool {
            self.session
                .as_ref()
                .is_some_and(PlatformTunHandle::is_ipv6_active)
        }

        #[cfg(target_os = "windows")]
        fn force_reconcile_uplink(&self) {
            if let Some(PlatformTunHandle::Windows(ref session)) = self.session {
                session.force_reconcile_uplink();
            }
        }

        async fn start(
            &mut self,
            binder: &Arc<DynamicOutboundBinder>,
            tun_ipv6: bool,
            explicit_dns_ipv4_only: bool,
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

                ctx.dns.set_ipv4_only(effective_tun_dns_ipv4_only(
                    explicit_dns_ipv4_only,
                    session.is_ipv6_active(),
                ));
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

                ctx.dns.set_ipv4_only(effective_tun_dns_ipv4_only(
                    explicit_dns_ipv4_only,
                    session.is_ipv6_active(),
                ));
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
                let (mut session, tun_fd) = tokio::task::spawn_blocking(move || {
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

                ctx.dns.set_ipv4_only(effective_tun_dns_ipv4_only(
                    explicit_dns_ipv4_only,
                    session.is_ipv6_active(),
                ));
                let route_rx = session.take_route_watch();
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
                    route_rx.clone(),
                    app_bypass,
                ));

                self.session = Some(PlatformTunHandle::Linux(session));
                self.pipeline_stop_tx = Some(stop_tx);
                self.pipeline_task = Some(pipeline_task);
                self.route_rx = route_rx;
                Ok(())
            }

            #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
            {
                let _ = (
                    binder,
                    tun_ipv6,
                    explicit_dns_ipv4_only,
                    ctx,
                    tun_stats,
                    events,
                );
                Err(format_tun_start_error(anyhow::anyhow!(
                    "desktop TUN mode is not supported on {}",
                    platform_name()
                )))
            }
        }

        async fn stop(&mut self) {
            #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
            {
                self.route_rx = None;
            }
            #[cfg(target_os = "linux")]
            if let Some(PlatformTunHandle::Linux(linux_tun)) = self.session.take() {
                if let Ok(returned) = tokio::task::spawn_blocking(move || {
                    #[allow(unused_mut)]
                    let mut linux_tun = linux_tun;
                    linux_tun.revert_dns_early();
                    linux_tun
                })
                .await
                {
                    self.session = Some(PlatformTunHandle::Linux(returned));
                }
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
                     - Extract all files from the official release zip keeping wintun.dll in the same folder as vdpi.exe (or run `vdpi update --force`).\n  \
                     - For source / `cargo install` builds, place the official WHQL-signed wintun.dll in the same folder as vdpi.exe.\n  \
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
                 Tip: Run elevated as Administrator with wintun.dll in the same folder as vdpi.exe (extract all files from the zip), or switch to Proxy mode with `vdpi --proxy start` (`vdpi engine proxy`)."
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
                 - Run with root privileges (`sudo vdpi --tun start`) or install the systemd system service (`sudo vdpi install --tun`).\n  \
                 - Note: bare `setcap cap_net_admin` on the binary alone is not sufficient because child `ip`/`resolvectl` helpers do not inherit file capabilities without ambient capabilities (even though non-root runtime state falls back to `$XDG_RUNTIME_DIR/vdpi`).\n  \
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

    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
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

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    async fn wait_route_change() {
        std::future::pending::<()>().await;
    }

    struct TunStartEnv {
        binder: Arc<DynamicOutboundBinder>,
        ctx: EngineContext,
        tun_stats: Arc<TunStats>,
        events: Arc<EventRing>,
        tun_ipv6: bool,
        explicit_dns_ipv4_only: bool,
        health_addr: SocketAddr,
    }

    struct TunRetryState {
        last_attempt: Option<Instant>,
        next_retry_at: Option<Instant>,
        consecutive_failures: u32,
        consecutive_pipeline_exits: u32,
        last_started_at: Option<Instant>,
        last_start_error: Option<(String, Instant)>,
        offline_standby_logged: bool,
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
                offline_standby_logged: false,
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
            if self.offline_standby_logged {
                info!("physical network uplink restored; TUN session is active");
                self.offline_standby_logged = false;
            }
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
            self.offline_standby_logged = false;
        }

        fn record_start_failure(&mut self, now: Instant, err: &anyhow::Error) {
            match classify_tun_start_error_log(&mut self.offline_standby_logged, err) {
                TunStartErrorLogAction::LogOfflineStandby => {
                    self.next_retry_at = Some(now + OFFLINE_STANDBY_RETRY_INTERVAL);
                    self.last_start_error = None;
                    warn!(
                        error = %err,
                        "no active physical network uplink; holding TUN in standby and polling for connectivity"
                    );
                }
                TunStartErrorLogAction::SuppressOfflineStandby => {
                    self.next_retry_at = Some(now + OFFLINE_STANDBY_RETRY_INTERVAL);
                }
                TunStartErrorLogAction::LogRetryableError => {
                    self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                    let backoff = retry_backoff(self.consecutive_failures);
                    self.next_retry_at = Some(now + backoff);
                    let err_text = format!("{err:#}");
                    let should_log = self.last_start_error.as_ref().is_none_or(|(prev, ts)| {
                        prev != &err_text
                            || now.saturating_duration_since(*ts) >= Duration::from_secs(30)
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
        }
    }

    enum LoopEvent {
        None,
        Reconcile,
        RouteChanged,
        PipelineExited,
        RetryStart,
        #[cfg(target_os = "windows")]
        PowerResume,
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
                env.explicit_dns_ipv4_only,
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
                    #[cfg(target_os = "windows")]
                    {
                        let _ = tokio::task::spawn_blocking(
                            vdpi::platform::windows_tun::cleanup_orphan_wintun_adapter,
                        )
                        .await;
                    }
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

    pub(super) fn normalize_tun_runtime_config(mut cfg: RuntimeConfig) -> RuntimeConfig {
        // When IPv6 TUN routing is disabled, force IPv4-only DNS answers so browsers
        // (Happy Eyeballs) on dual-stack ISPs do not leak AAAA connections past vdpi0.
        if !cfg.tun_ipv6 {
            cfg.dns_ipv4_only = true;
        }
        cfg
    }

    pub(super) async fn run_tun_daemon(
        cfg: RuntimeConfig,
        dashboard_tracing: Option<DashboardTracing>,
    ) -> Result<()> {
        let explicit_dns_ipv4_only = cfg.dns_ipv4_only;
        let cfg = normalize_tun_runtime_config(cfg);
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
        let mut initial_retry = TunRetryState::new(false);

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
                match slot
                    .start(
                        &binder,
                        cfg.tun_ipv6,
                        explicit_dns_ipv4_only,
                        &ctx,
                        &tun_stats,
                        &events,
                    )
                    .await
                {
                    Ok(()) => initial_retry.record_started(Instant::now()),
                    Err(err) if is_fatal_tun_start_error(&err) => {
                        #[cfg(target_os = "windows")]
                        {
                            let _ = tokio::task::spawn_blocking(
                                vdpi::platform::windows_tun::cleanup_orphan_wintun_adapter,
                            )
                            .await;
                        }
                        return Err(err);
                    }
                    Err(err) => {
                        let now = Instant::now();
                        initial_retry.last_attempt = Some(now);
                        initial_retry.record_start_failure(now, &err);
                    }
                }
            }
            GuardAction::None | GuardAction::ResumeTun => {
                match slot
                    .start(
                        &binder,
                        cfg.tun_ipv6,
                        explicit_dns_ipv4_only,
                        &ctx,
                        &tun_stats,
                        &events,
                    )
                    .await
                {
                    Ok(()) => initial_retry.record_started(Instant::now()),
                    Err(err) if is_fatal_tun_start_error(&err) => {
                        #[cfg(target_os = "windows")]
                        {
                            let _ = tokio::task::spawn_blocking(
                                vdpi::platform::windows_tun::cleanup_orphan_wintun_adapter,
                            )
                            .await;
                        }
                        return Err(err);
                    }
                    Err(err) => {
                        let now = Instant::now();
                        initial_retry.last_attempt = Some(now);
                        initial_retry.record_start_failure(now, &err);
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        if !slot.is_running() {
            // Clean up any orphaned vdpi0 adapter left behind by a prior crash so it cannot
            // blackhole traffic while TUN is held in VPN-yielded or offline preflight standby.
            let _ = tokio::task::spawn_blocking(
                vdpi::platform::windows_tun::cleanup_orphan_wintun_adapter,
            )
            .await;
        }

        #[cfg(target_os = "linux")]
        if !slot.is_running() {
            // Clean up any orphaned Linux TUN routes/rules/DNS state left behind by a prior
            // crash so it cannot blackhole traffic while TUN is held in VPN-yielded or offline
            // standby.
            let _ = tokio::task::spawn_blocking(
                vdpi::platform::linux_tun::cleanup_linux_tun_state,
            )
            .await;
        }

        #[cfg(target_os = "windows")]
        {
            // Clear any leftover WinINET/WinHTTP/user-env proxy settings once when running in TUN mode.
            let _ = tokio::task::spawn_blocking(
                vdpi::platform::windows::clear_all_windows_proxies,
            )
            .await;
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
            dns_addr: Some(cfg.dns_addr.clone()),
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
                doh = vdpi_core::dns::is_effective_doh_target(&cfg.dns_addr, cfg.enable_doh),
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
            explicit_dns_ipv4_only,
            health_addr,
        };
        let sup_meta = Arc::clone(&health_meta);
        let sup_shutdown_tx = shutdown_tx.clone();
        let mut sup_shutdown_rx = shutdown_rx.clone();
        let vpn_policy = cfg.vpn_coexistence;
        let mut last_scope = initial_scope;

        let supervisor_task: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
            #[cfg(target_os = "windows")]
            let (mut power_resume_rx, _power_notify_guard, mut power_resume_open) = {
                let (tx, rx) = watch::channel::<u64>(0);
                let guard = windows_power::SuspendResumeNotificationGuard::register(tx);
                let open = guard.is_some();
                (rx, guard, open)
            };

            let mut telemetry_tick = tokio::time::interval(Duration::from_millis(250));
            telemetry_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut next_reconcile_at = tokio::time::Instant::now()
                + tun_reconcile_interval(slot.is_running(), vpn_guard.is_yielded());

            let mut retry = initial_retry;
            let mut fatal_error: Option<anyhow::Error> = None;

            loop {
                if *sup_shutdown_rx.borrow() {
                    break;
                }

                let desired_interval =
                    tun_reconcile_interval(slot.is_running(), vpn_guard.is_yielded());
                let max_deadline = tokio::time::Instant::now() + desired_interval;
                if next_reconcile_at > max_deadline {
                    next_reconcile_at = max_deadline;
                }

                let event = {
                    let pipeline_task = &mut slot.pipeline_task;
                    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
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
                        power_changed = async {
                            #[cfg(target_os = "windows")]
                            {
                                if power_resume_open {
                                    power_resume_rx.changed().await.is_ok()
                                } else {
                                    std::future::pending().await
                                }
                            }
                            #[cfg(not(target_os = "windows"))]
                            {
                                std::future::pending::<bool>().await
                            }
                        } => {
                            if power_changed {
                                #[cfg(target_os = "windows")]
                                {
                                    LoopEvent::PowerResume
                                }
                                #[cfg(not(target_os = "windows"))]
                                {
                                    LoopEvent::None
                                }
                            } else {
                                #[cfg(target_os = "windows")]
                                {
                                    power_resume_open = false;
                                }
                                LoopEvent::None
                            }
                        }
                        _ = async {
                            #[cfg(any(
                                target_os = "windows",
                                target_os = "macos",
                                target_os = "linux"
                            ))]
                            {
                                wait_route_change(route_rx).await;
                            }
                            #[cfg(not(any(
                                target_os = "windows",
                                target_os = "macos",
                                target_os = "linux"
                            )))]
                            {
                                wait_route_change().await;
                            }
                        } => {
                            LoopEvent::RouteChanged
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
                        _ = tokio::time::sleep_until(next_reconcile_at) => {
                            next_reconcile_at = tokio::time::Instant::now() + desired_interval;
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

                #[cfg(target_os = "windows")]
                let (is_power_resume, was_running_before_wake) = (
                    matches!(event, LoopEvent::PowerResume),
                    slot.is_running(),
                );

                match event {
                    LoopEvent::None => continue,
                    #[cfg(target_os = "windows")]
                    LoopEvent::PowerResume => {
                        sup_env.ctx.dns.clear_cache().await;
                        retry.last_attempt = None;
                        retry.next_retry_at = None;
                        if vpn_policy == VpnCoexistence::Off {
                            if slot.is_running() {
                                slot.force_reconcile_uplink();
                                let _ = tokio::task::spawn_blocking(
                                    vdpi::platform::windows::flush_dns_resolver_cache,
                                )
                                .await;
                            } else {
                                let now = Instant::now();
                                match try_start_slot(
                                    &mut slot,
                                    &sup_env,
                                    &sup_shutdown_rx,
                                    &mut retry,
                                    now,
                                    "resumed TUN mode after system wake",
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
                    }
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
                    LoopEvent::RouteChanged => {
                        let tun_ipv6_active = slot.is_ipv6_active();
                        if sync_tun_dns_ipv4_only_if_changed(
                            &sup_env.ctx.dns,
                            slot.is_running(),
                            sup_env.explicit_dns_ipv4_only,
                            tun_ipv6_active,
                            || async {
                                #[cfg(target_os = "windows")]
                                {
                                    let _ = tokio::task::spawn_blocking(
                                        vdpi::platform::windows::flush_dns_resolver_cache,
                                    )
                                    .await;
                                }
                            },
                        )
                        .await
                        {
                            debug!(
                                ipv4_only = sup_env.ctx.dns.is_ipv4_only(),
                                tun_ipv6_active,
                                "re-synced TUN DNS IPv4-only filtering after route change"
                            );
                        }
                        if vpn_policy == VpnCoexistence::Off {
                            continue;
                        }
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
                            #[cfg(target_os = "linux")]
                            {
                                let _ = tokio::task::spawn_blocking(
                                    vdpi::platform::linux_tun::cleanup_linux_tun_state,
                                )
                                .await;
                            }
                        }
                        sup_env.ctx.dns.clear_cache().await;
                    }
                    GuardAction::ResumeTun => {
                        last_warned_provider = None;
                        retry.consecutive_pipeline_exits = 0;
                        sup_env.ctx.dns.clear_cache().await;
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

                #[cfg(target_os = "windows")]
                if is_power_resume && was_running_before_wake && slot.is_running() {
                    slot.force_reconcile_uplink();
                    let _ = tokio::task::spawn_blocking(
                        vdpi::platform::windows::flush_dns_resolver_cache,
                    )
                    .await;
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
                enable_doh: vdpi_core::dns::is_effective_doh_target(&cfg.dns_addr, cfg.enable_doh),
                dns_addr: Some(cfg.dns_addr.clone()),
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
            super::format_dns_resolution_line(&cfg.dns_addr, cfg.dns_port, cfg.enable_doh)
        );
        println!("  VPN Coexistence     : {}", cfg.vpn_coexistence.as_str());
        if let Some(vpn) = vpn_conflict {
            println!("  VPN Status          : {vpn}");
        }
        println!();
    }
}

fn format_dns_resolution_line(dns_addr: &str, dns_port: u16, enable_doh: bool) -> String {
    let display_addr = vdpi_core::dns::redact_dns_for_display(dns_addr);
    if vdpi_core::dns::is_effective_doh_target(dns_addr, enable_doh) {
        format!("RFC 8484 DoH ({display_addr}) + non-53 UDP fallback")
    } else if display_addr.contains(':') && !display_addr.starts_with('[') {
        format!("UDP ([{display_addr}]:{dns_port})")
    } else {
        format!("UDP ({display_addr}:{dns_port})")
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
        format_dns_resolution_line(&cfg.dns_addr, cfg.dns_port, cfg.enable_doh)
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
        .with_writer(std::io::stderr)
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
        #[cfg(target_os = "windows")]
        {
            assert!(!msg.to_ascii_lowercase().contains("embed"));
            assert!(msg.contains("wintun.dll"));
            assert!(msg.contains("zip"));
        }

        let priv_err =
            desktop_tun::format_tun_start_error(anyhow::anyhow!("Access is denied (os error 5)"));
        let priv_msg = priv_err.to_string();
        assert!(priv_msg.contains("--proxy"));
        #[cfg(target_os = "linux")]
        {
            assert!(priv_msg.contains("sudo vdpi --tun start"));
            assert!(priv_msg.contains("sudo vdpi install --tun"));
            assert!(priv_msg.contains("$XDG_RUNTIME_DIR/vdpi"));
            assert!(!priv_msg.contains("root access to `/run/vdpi`"));
            assert!(!priv_msg.contains("sudo setcap"));
        }
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn desktop_tun_forces_dns_ipv4_only_when_tun_ipv6_disabled() {
        let ipv4_tun = RuntimeConfig {
            engine: EngineMode::Tun,
            tun_ipv6: false,
            dns_ipv4_only: false,
            ..RuntimeConfig::default()
        };
        let explicit_v4_default = ipv4_tun.dns_ipv4_only;
        let normalized = desktop_tun::normalize_tun_runtime_config(ipv4_tun);
        assert!(normalized.dns_ipv4_only);
        // Capturing `explicit_dns_ipv4_only` before normalization lets IPv6-only uplinks
        // that auto-enable IPv6 TUN (`session_ipv6_active = true`) resolve AAAA records.
        assert!(!desktop_tun::effective_tun_dns_ipv4_only(
            explicit_v4_default,
            true
        ));
        assert!(desktop_tun::effective_tun_dns_ipv4_only(
            explicit_v4_default,
            false
        ));

        // Explicit `--ipv4-only` must be preserved even when TUN IPv6 is active or roams on.
        assert!(desktop_tun::effective_tun_dns_ipv4_only(true, true));
        assert!(desktop_tun::effective_tun_dns_ipv4_only(true, false));

        let dual_tun = RuntimeConfig {
            engine: EngineMode::Tun,
            tun_ipv6: true,
            dns_ipv4_only: false,
            ..RuntimeConfig::default()
        };
        let normalized_dual = desktop_tun::normalize_tun_runtime_config(dual_tun);
        assert!(!normalized_dual.dns_ipv4_only);
    }

    #[test]
    fn config_get_evaluates_cli_over_file_over_default() {
        let file_cfg = FileConfig {
            schema_version: Some(CONFIG_SCHEMA_VERSION),
            engine: Some(EngineMode::Proxy),
            port: Some(8088),
            ..Default::default()
        };
        let raw_args = vec![
            "--tun".to_string(),
            "--port".to_string(),
            "9090".to_string(),
            "config".to_string(),
            "get".to_string(),
            "port".to_string(),
        ];
        let mut argv = vec!["vdpi".to_string()];
        argv.extend(raw_args.iter().cloned());
        let cli = CliArgs::parse_from_iter(&argv).unwrap();
        assert_eq!(
            resolve_effective_config_key(cli.clone(), &file_cfg, &raw_args, "port")
                .unwrap()
                .as_deref(),
            Some("9090")
        );
        assert_eq!(
            resolve_effective_config_key(cli, &file_cfg, &raw_args, "engine")
                .unwrap()
                .as_deref(),
            Some("tun")
        );
    }

    #[test]
    fn foreground_tokio_worker_threads_is_clamped_for_audio_safety() {
        let workers = foreground_tokio_worker_threads();
        assert!((2..=4).contains(&workers));
    }

    #[test]
    fn resolve_dns_target_accepts_presets_ips_and_doh_urls() {
        assert_eq!(resolve_dns_target("cloudflare").unwrap(), "1.1.1.1");
        assert_eq!(resolve_dns_target("Google").unwrap(), "8.8.8.8");
        assert_eq!(
            resolve_dns_target("adguard-unfiltered").unwrap(),
            "94.140.14.140"
        );
        assert_eq!(resolve_dns_target("family").unwrap(), "1.1.1.3");
        assert_eq!(resolve_dns_target("9.9.9.9").unwrap(), "9.9.9.9");
        assert_eq!(
            resolve_dns_target("2606:4700:4700::1111").unwrap(),
            "2606:4700:4700::1111"
        );
        assert_eq!(
            resolve_dns_target("https://dns.nextdns.io/abc123/my-profile").unwrap(),
            "https://dns.nextdns.io/abc123/my-profile"
        );
        assert!(resolve_dns_target("").is_err());
        assert!(resolve_dns_target("not a valid dns").is_err());
        assert!(resolve_dns_target("http://insecure.example/dns-query").is_err());
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
            dns_addr: None,
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
            dns_addr: Some("94.140.14.14".to_string()),
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
        assert_eq!(info.dns_addr.as_deref(), Some("94.140.14.14"));
        assert_eq!(
            info.engine,
            tui_dashboard::DashboardEngine::Tun {
                interface: "vdpi0".to_string(),
                physical_nic: Some("Ethernet".to_string()),
                vpn_conflict: None,
            }
        );

        let attached = attached_telemetry_from_live(&tun_live, &fallback_cfg);
        assert_eq!(attached.dns_addr.as_deref(), Some("94.140.14.14"));
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

        let (remaining, removed) =
            remove_split_tunnel_apps(&merged, &["discord".to_string(), "STEAM.EXE".to_string()])
                .unwrap();
        assert_eq!(removed, 2);
        assert_eq!(remaining, vec!["firefox.exe".to_string()]);
    }

    #[test]
    fn dns_banner_uses_effective_enable_doh_and_redacts_custom_url() {
        let doh_line = format_dns_resolution_line(
            "https://dns.nextdns.io/secret-token/my-profile",
            53,
            false,
        );
        assert!(doh_line.starts_with("RFC 8484 DoH ("));
        assert!(!doh_line.contains("UDP (https://"));
        assert!(!doh_line.contains(":53)"));
        assert!(doh_line.contains("dns.nextdns.io"));
        assert!(!doh_line.contains("secret-token"));
        assert!(!doh_line.contains("my-profile"));

        assert_eq!(
            format_dns_resolution_line("1.1.1.1", 53, false),
            "UDP (1.1.1.1:53)"
        );
        assert_eq!(
            format_dns_resolution_line("1.1.1.1", 53, true),
            "RFC 8484 DoH (1.1.1.1) + non-53 UDP fallback"
        );
        assert_eq!(
            format_dns_resolution_line("2606:4700:4700::1111", 53, false),
            "UDP ([2606:4700:4700::1111]:53)"
        );
        // Bare custom non-DoH IPs must report UDP even when enable_doh is true.
        assert_eq!(
            format_dns_resolution_line("76.76.2.0", 53, true),
            "UDP (76.76.2.0:53)"
        );
        assert_eq!(
            format_dns_resolution_line("2606:1a40::", 53, true),
            "UDP ([2606:1a40::]:53)"
        );
    }

    #[test]
    fn resolve_dns_target_redacts_tokens_in_error_messages() {
        let http_err =
            resolve_dns_target("http://user:secretpass@dns.nextdns.io/my-secret-token/profile")
                .unwrap_err()
                .to_string();
        assert!(http_err.contains("http://dns.nextdns.io"));
        assert!(!http_err.contains("secretpass"));
        assert!(!http_err.contains("my-secret-token"));
        assert!(!http_err.contains("profile"));

        let malformed_err = resolve_dns_target("https://bad_host/top-secret-token")
            .unwrap_err()
            .to_string();
        assert!(malformed_err.contains("https://<redacted>"));
        assert!(!malformed_err.contains("top-secret-token"));

        let whitespace_err = resolve_dns_target("https://bad host/top-secret-token")
            .unwrap_err()
            .to_string();
        assert!(!whitespace_err.contains("top-secret-token"));
    }

    #[test]
    fn wintun_preflight_notice_is_concise_without_raw_paths_or_hashes() {
        let hash_err = "wintun.dll SHA-256 verification failed for C:\\Users\\Alice\\Downloads\\vdpi\\wintun.dll: expected 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef, got fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        let notice = format_wintun_preflight_notice(hash_err);
        assert_eq!(
            notice,
            "wintun.dll is corrupted or mismatched - extract all files from the zip (keep wintun.dll beside vdpi.exe)"
        );
        assert!(!notice.contains("C:\\Users"));
        assert!(!notice.contains("0123456789abcdef"));

        let missing = format_wintun_preflight_notice(
            "wintun.dll (v0.14.1) not found beside vdpi executable or runtime cache",
        );
        assert_eq!(
            missing,
            "wintun.dll not found next to vdpi.exe - extract all files from the zip"
        );
    }

    #[test]
    fn foreground_proxy_vpn_poll_interval_matches_three_second_cadence() {
        assert_eq!(FOREGROUND_PROXY_VPN_POLL_INTERVAL, Duration::from_secs(3));
    }

    #[test]
    fn explicit_config_path_overrides_probed_engine_and_dns_display() {
        let explicit = Path::new("custom.toml");
        assert_eq!(
            configured_engine_for_display(Some(explicit), EngineMode::Tun, EngineMode::Proxy),
            EngineMode::Tun
        );
        assert_eq!(
            configured_engine_for_display(None, EngineMode::Tun, EngineMode::Proxy),
            EngineMode::Proxy
        );
        assert_eq!(
            configured_dns_for_display(Some(explicit), "76.76.2.0"),
            "76.76.2.0"
        );
    }

    #[test]
    fn split_command_respects_explicit_config_path_and_cli_overrides() {
        let dir = std::env::temp_dir().join(format!(
            "vdpi-main-split-cfg-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg_path = dir.join("config.toml");

        handle_split_command(
            Some(SplitCommand::Mode {
                mode: SplitTunnelMode::Exclude,
            }),
            Some(&cfg_path),
            None,
            &[],
        )
        .unwrap();
        handle_split_command(
            Some(SplitCommand::Add {
                apps: vec!["discord.exe".to_string()],
            }),
            Some(&cfg_path),
            None,
            &[],
        )
        .unwrap();

        let loaded = load_effective_split_tunnel(Some(&cfg_path), None, &[], false).unwrap();
        assert_eq!(loaded.mode, SplitTunnelMode::Exclude);
        assert_eq!(loaded.apps, vec!["discord.exe".to_string()]);

        let overridden = load_effective_split_tunnel(
            Some(&cfg_path),
            Some(SplitTunnelMode::Include),
            &["firefox.exe".to_string()],
            false,
        )
        .unwrap();
        assert_eq!(overridden.mode, SplitTunnelMode::Include);
        assert_eq!(overridden.apps, vec!["firefox.exe".to_string()]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_split_tunnel_apps_strips_shortcut_cli_arguments() {
        let existing = vec![
            "RiotClientServices.exe".to_string(),
            "Discord.exe".to_string(),
            "firefox".to_string(),
            "steam.exe".to_string(),
        ];
        let (remaining, removed) = remove_split_tunnel_apps(
            &existing,
            &[
                r#""C:\Riot Games\Riot Client\RiotClientServices.exe" --launch-product=valorant --launch-patchline=live"#
                    .to_string(),
                r"C:\Program Files\Discord\Discord.exe --start-minimized".to_string(),
                "'/usr/bin/firefox' --new-window".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(removed, 3);
        assert_eq!(remaining, vec!["steam.exe".to_string()]);
    }

    #[test]
    fn split_remove_rejects_invalid_args_and_skips_write_on_zero_matches() {
        let existing = vec!["Discord.exe".to_string()];

        // Reject empty, whitespace, mixed empty, control-char, and non-name inputs.
        assert!(remove_split_tunnel_apps(&existing, &[]).is_err());
        assert!(remove_split_tunnel_apps(&existing, &[String::new()]).is_err());
        assert!(remove_split_tunnel_apps(&existing, &["   ".to_string()]).is_err());
        assert!(
            remove_split_tunnel_apps(&existing, &["discord.exe".to_string(), "  ".to_string()])
                .is_err()
        );
        assert!(remove_split_tunnel_apps(&existing, &["discord\n".to_string()]).is_err());
        assert!(remove_split_tunnel_apps(&existing, &["discord\x00.exe".to_string()]).is_err());
        assert!(remove_split_tunnel_apps(&existing, &["..".to_string()]).is_err());

        // Non-matching valid app returns unchanged list with 0 removed.
        let (remaining, removed) =
            remove_split_tunnel_apps(&existing, &["steam.exe".to_string()]).unwrap();
        assert_eq!(removed, 0);
        assert_eq!(remaining, existing);

        let dir = std::env::temp_dir().join(format!(
            "vdpi-main-split-remove-noop-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg_path = dir.join("config.toml");

        // Removing from a missing explicit config with 0 matches must not create config.toml.
        handle_split_command(
            Some(SplitCommand::Remove {
                apps: vec!["steam.exe".to_string()],
            }),
            Some(&cfg_path),
            None,
            &[],
        )
        .unwrap();
        assert!(!cfg_path.exists());

        // Existing file with sentinel comment must not be rewritten on invalid args or 0 matches.
        std::fs::create_dir_all(&dir).unwrap();
        let sentinel_toml =
            "# keep-sentinel-comment\nsplit_tunnel_mode = \"exclude\"\nsplit_tunnel_apps = [\"Discord.exe\"]\n";
        std::fs::write(&cfg_path, sentinel_toml).unwrap();

        assert!(handle_split_command(
            Some(SplitCommand::Remove {
                apps: vec!["   ".to_string()],
            }),
            Some(&cfg_path),
            None,
            &[],
        )
        .is_err());
        assert!(handle_split_command(
            Some(SplitCommand::Remove {
                apps: vec!["discord\n".to_string()],
            }),
            Some(&cfg_path),
            None,
            &[],
        )
        .is_err());
        handle_split_command(
            Some(SplitCommand::Remove {
                apps: vec!["steam.exe".to_string()],
            }),
            Some(&cfg_path),
            None,
            &[],
        )
        .unwrap();
        let after_noop = std::fs::read_to_string(&cfg_path).unwrap();
        assert_eq!(after_noop, sentinel_toml);

        // Matching removal updates and rewrites config.toml.
        handle_split_command(
            Some(SplitCommand::Remove {
                apps: vec!["discord".to_string()],
            }),
            Some(&cfg_path),
            None,
            &[],
        )
        .unwrap();
        let loaded = load_effective_split_tunnel(Some(&cfg_path), None, &[], false).unwrap();
        assert!(loaded.apps.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn elevated_invoking_user_resolves_sudo_pkexec_and_doas() {
        let alice = ElevatedUserInfo {
            uid: 1000,
            gid: 1000,
            home_dir: PathBuf::from("/home/alice"),
        };
        let bob = ElevatedUserInfo {
            uid: 1001,
            gid: 1001,
            home_dir: PathBuf::from("/home/bob"),
        };
        let by_uid = |uid: u32| match uid {
            1000 => Some(alice.clone()),
            1001 => Some(bob.clone()),
            _ => None,
        };
        let by_name = |name: &str| match name {
            "alice" => Some(alice.clone()),
            "bob" => Some(bob.clone()),
            _ => None,
        };

        // PKEXEC_UID resolves invoking user when SUDO_* is absent.
        assert_eq!(
            resolve_elevated_invoking_user_with(
                None,
                None,
                Some("1000"),
                None,
                0,
                by_uid,
                by_name,
            ),
            Some(alice.clone())
        );

        // Unknown PKEXEC_UID and SUDO_UID return None instead of trusting $HOME.
        assert_eq!(
            resolve_elevated_invoking_user_with(
                None,
                None,
                Some("2000"),
                None,
                0,
                by_uid,
                by_name,
            ),
            None
        );
        assert_eq!(
            resolve_elevated_invoking_user_with(
                Some("2000"),
                None,
                None,
                None,
                0,
                by_uid,
                by_name,
            ),
            None
        );

        // DOAS_USER resolves invoking user via name lookup.
        assert_eq!(
            resolve_elevated_invoking_user_with(
                None,
                None,
                None,
                Some("bob"),
                0,
                by_uid,
                by_name,
            ),
            Some(bob.clone())
        );

        // Non-zero real_uid resolves via passwd lookup (macOS osascript / setuid path).
        assert_eq!(
            resolve_elevated_invoking_user_with(
                None,
                None,
                None,
                None,
                1000,
                by_uid,
                by_name,
            ),
            Some(alice.clone())
        );

        // Unknown real_uid returns None when passwd lookup misses.
        assert_eq!(
            resolve_elevated_invoking_user_with(
                None,
                None,
                None,
                None,
                2000,
                by_uid,
                by_name,
            ),
            None
        );

        // SUDO_UID takes precedence over real_uid.
        assert_eq!(
            resolve_elevated_invoking_user_with(
                Some("1001"),
                None,
                None,
                None,
                1000,
                by_uid,
                by_name,
            ),
            Some(bob.clone())
        );

        // Root UID 0, "root", and invalid paths are ignored.
        assert_eq!(
            resolve_elevated_invoking_user_with(
                Some("0"),
                Some("root"),
                Some("0"),
                Some("root"),
                0,
                by_uid,
                by_name,
            ),
            None
        );
        assert_eq!(
            resolve_elevated_invoking_user_with(
                None,
                None,
                None,
                Some("../alice"),
                0,
                by_uid,
                by_name,
            ),
            None
        );
    }

    #[test]
    fn verify_no_symlink_under_home_rejects_traversal_and_symlinks() {
        let base = std::env::temp_dir().join(format!(
            "vdpi-main-symlink-check-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        let outside = base.join("outside");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        // Non-existent nested config path under home is allowed and missing dirs are collected top-down.
        let nested_cfg = home.join(".config").join("vdpi").join("config.toml");
        assert!(verify_no_symlink_under_home(&nested_cfg, &home).is_ok());
        assert_eq!(
            collect_missing_dirs_under_home(nested_cfg.parent().unwrap(), &home),
            vec![home.join(".config"), home.join(".config").join("vdpi")]
        );

        // Parent traversal `..` under user home is rejected.
        let traversal = home.join(".config").join("..").join("outside").join("config.toml");
        assert!(verify_no_symlink_under_home(&traversal, &home).is_err());

        // Path outside home is unaffected.
        assert!(verify_no_symlink_under_home(&outside.join("config.toml"), &home).is_ok());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let symlink_parent = home.join(".config");
            symlink(&outside, &symlink_parent).unwrap();
            assert!(verify_no_symlink_under_home(&nested_cfg, &home).is_err());
            let _ = std::fs::remove_file(&symlink_parent);

            let real_dir = home.join(".config").join("vdpi");
            std::fs::create_dir_all(&real_dir).unwrap();
            let symlink_file = real_dir.join("config.toml");
            symlink(outside.join("target.toml"), &symlink_file).unwrap();
            assert!(verify_no_symlink_under_home(&symlink_file, &home).is_err());
        }

        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    #[test]
    fn foreground_proxy_spec_forwards_include_domains_and_vpn_coexistence() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use vdpi::config::VpnCoexistence;

        let cfg = RuntimeConfig {
            bypass_domains: vec!["local.example".to_string()],
            patterns: vec!["^example\\.org\\.tr$".to_string()],
            vpn_coexistence: VpnCoexistence::Warn,
            socks_system_proxy: true,
            ..RuntimeConfig::default()
        };
        let primary = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080);
        let socks = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080));
        let spec = ForegroundProxySpec::from_runtime_config(&cfg, primary, socks);
        assert_eq!(
            spec.proxy_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
        );
        assert_eq!(spec.bypass_domains, vec!["local.example".to_string()]);
        assert_eq!(spec.include_domains, vec!["^example\\.org\\.tr$".to_string()]);
        assert_eq!(spec.vpn_coexistence, VpnCoexistence::Warn);

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let unix_spec = spec.to_unix_spec();
            assert_eq!(unix_spec.socks_port, Some(1080));
            assert_eq!(unix_spec.include_domains, cfg.patterns);
            assert_eq!(unix_spec.vpn_coexistence, VpnCoexistence::Warn);
        }
    }

    #[test]
    fn yielded_recovery_poll_intervals_shorten_to_one_second() {
        assert_eq!(
            foreground_proxy_vpn_poll_interval(false),
            Duration::from_secs(3)
        );
        assert_eq!(
            foreground_proxy_vpn_poll_interval(true),
            Duration::from_secs(1)
        );

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            assert_eq!(
                desktop_tun::tun_reconcile_interval(true, false),
                Duration::from_secs(3)
            );
            assert_eq!(
                desktop_tun::tun_reconcile_interval(false, false),
                Duration::from_secs(1)
            );
            assert_eq!(
                desktop_tun::tun_reconcile_interval(true, true),
                Duration::from_secs(1)
            );
            assert_eq!(
                desktop_tun::tun_reconcile_interval(false, true),
                Duration::from_secs(1)
            );
        }
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn tun_offline_standby_warning_is_deduplicated_until_recovered_or_changed() {
        let mut logged = false;
        let win_offline = anyhow::anyhow!(
            "no active physical network uplink detected; connect to Wi-Fi or Ethernet and retry"
        );
        let mac_offline = anyhow::anyhow!(
            "no physical default IPv4 or IPv6 interface found (disconnect any active VPN holding the default route)"
        );
        let transient_other = anyhow::anyhow!("temporary routing table lock contention");

        assert_eq!(
            desktop_tun::classify_tun_start_error_log(&mut logged, &win_offline),
            desktop_tun::TunStartErrorLogAction::LogOfflineStandby
        );
        assert!(logged);
        assert_eq!(
            desktop_tun::classify_tun_start_error_log(&mut logged, &win_offline),
            desktop_tun::TunStartErrorLogAction::SuppressOfflineStandby
        );
        assert_eq!(
            desktop_tun::classify_tun_start_error_log(&mut logged, &mac_offline),
            desktop_tun::TunStartErrorLogAction::SuppressOfflineStandby
        );
        assert_eq!(
            desktop_tun::classify_tun_start_error_log(&mut logged, &transient_other),
            desktop_tun::TunStartErrorLogAction::LogRetryableError
        );
        assert!(!logged);
        assert_eq!(
            desktop_tun::classify_tun_start_error_log(&mut logged, &win_offline),
            desktop_tun::TunStartErrorLogAction::LogOfflineStandby
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_foreground_tun_power_resume_event_filter() {
        assert!(
            desktop_tun::windows_power::should_trigger_power_resume_reconcile(
                desktop_tun::windows_power::PBT_APMRESUMEAUTOMATIC
            )
        );
        assert!(
            desktop_tun::windows_power::should_trigger_power_resume_reconcile(
                desktop_tun::windows_power::PBT_APMRESUMESUSPEND
            )
        );
        assert!(!desktop_tun::windows_power::should_trigger_power_resume_reconcile(0x0000_0004));
        assert!(!desktop_tun::windows_power::should_trigger_power_resume_reconcile(0x0000_000A));
    }

    #[test]
    fn chown_targets_strictly_restricted_to_user_home_dir() {
        let base = std::env::temp_dir().join(format!(
            "vdpi-main-chown-allowlist-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        let outside = base.join("outside");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let user_cfg = home.join(".config").join("vdpi").join("config.toml");

        // Normal user config strictly beneath home collects ancestors (excluding home itself) and file.
        assert!(is_safe_chown_target_under_home(&user_cfg, &home));
        assert_eq!(
            collect_chown_targets_under_home(&user_cfg, &[], &user_cfg, &home),
            vec![
                home.join(".config"),
                home.join(".config").join("vdpi"),
                user_cfg.clone(),
            ]
        );

        // Paths outside user home are NEVER eligible for lchown (neither file nor parent),
        // even if `user_cfg_path` was redirected outside home (e.g. XDG_CONFIG_HOME=/etc).
        let outside_cfg = outside.join("vdpi").join("config.toml");
        assert!(!is_safe_chown_target_under_home(&outside_cfg, &home));
        assert!(collect_chown_targets_under_home(
            &outside_cfg,
            &[outside.join("vdpi")],
            &outside_cfg,
            &home
        )
        .is_empty());

        // Parent traversal (`..`) under home is rejected for both file and created_dirs.
        let traversal = home
            .join(".config")
            .join("..")
            .join("outside")
            .join("config.toml");
        assert!(!is_safe_chown_target_under_home(&traversal, &home));
        assert!(collect_chown_targets_under_home(&traversal, &[], &traversal, &home).is_empty());

        // Injected outside or traversal entries in created_dirs are filtered out.
        let custom_under_home = home.join("custom").join("vdpi.toml");
        assert_eq!(
            collect_chown_targets_under_home(
                &custom_under_home,
                &[
                    outside.join("vdpi"),
                    home.join("custom").join("..").join("outside"),
                    home.join("custom"),
                ],
                &user_cfg,
                &home
            ),
            vec![home.join("custom"), custom_under_home.clone()]
        );

        // Home directory itself (and `.` alias) or invalid home dirs are rejected.
        assert!(!is_safe_chown_target_under_home(&home, &home));
        assert!(!is_safe_chown_target_under_home(&home.join("."), &home));
        assert!(!is_safe_chown_target_under_home(
            &user_cfg,
            Path::new("relative/home")
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let symlink_parent = home.join(".config");
            symlink(&outside, &symlink_parent).unwrap();
            assert!(!is_safe_chown_target_under_home(&user_cfg, &home));
            assert!(collect_chown_targets_under_home(&user_cfg, &[], &user_cfg, &home).is_empty());
            let _ = std::fs::remove_file(&symlink_parent);

            let real_dir = home.join(".config").join("vdpi");
            std::fs::create_dir_all(&real_dir).unwrap();
            let symlink_file = real_dir.join("config.toml");
            symlink(outside.join("target.toml"), &symlink_file).unwrap();
            assert!(!is_safe_chown_target_under_home(&symlink_file, &home));
            assert!(
                collect_chown_targets_under_home(&symlink_file, &[], &symlink_file, &home)
                    .is_empty()
            );
        }

        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[tokio::test]
    async fn foreground_tun_route_change_sync_flushes_os_dns_cache_on_ipv4_only_toggle() {
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
        use std::sync::Arc;

        let ctx = EngineContext::new(RuntimeConfig {
            tun_ipv6: false,
            dns_ipv4_only: true,
            ..RuntimeConfig::default()
        })
        .expect("EngineContext::new should succeed for default config");
        assert!(ctx.dns.is_ipv4_only());

        // Stopped TUN slot must not mutate DNS filtering or flush OS cache.
        let flushes = Arc::new(AtomicU32::new(0));
        let flushes_clone = Arc::clone(&flushes);
        let changed = desktop_tun::sync_tun_dns_ipv4_only_if_changed(
            &ctx.dns,
            false,
            false,
            true,
            move || async move {
                flushes_clone.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert!(!changed);
        assert!(ctx.dns.is_ipv4_only());
        assert_eq!(flushes.load(Ordering::SeqCst), 0);

        // No-op when effective ipv4_only matches current state (true -> true).
        let flushes_clone = Arc::clone(&flushes);
        let changed = desktop_tun::sync_tun_dns_ipv4_only_if_changed(
            &ctx.dns,
            true,
            false,
            false,
            move || async move {
                flushes_clone.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert!(!changed);
        assert!(ctx.dns.is_ipv4_only());
        assert_eq!(flushes.load(Ordering::SeqCst), 0);

        // Transition true -> false must flip ipv4_only BEFORE flushing OS DNS cache.
        let flushes_clone = Arc::clone(&flushes);
        let ipv4_only_seen_at_flush = Arc::new(AtomicBool::new(true));
        let ipv4_only_seen_clone = Arc::clone(&ipv4_only_seen_at_flush);
        let dns_ref = &ctx.dns;
        let changed = desktop_tun::sync_tun_dns_ipv4_only_if_changed(
            dns_ref,
            true,
            false,
            true,
            move || async move {
                ipv4_only_seen_clone.store(dns_ref.is_ipv4_only(), Ordering::SeqCst);
                flushes_clone.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert!(changed);
        assert!(!ctx.dns.is_ipv4_only());
        assert!(!ipv4_only_seen_at_flush.load(Ordering::SeqCst));
        assert_eq!(flushes.load(Ordering::SeqCst), 1);

        // Repeated route change with unchanged IPv6 state must not re-flush.
        let flushes_clone = Arc::clone(&flushes);
        let changed = desktop_tun::sync_tun_dns_ipv4_only_if_changed(
            &ctx.dns,
            true,
            false,
            true,
            move || async move {
                flushes_clone.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert!(!changed);
        assert!(!ctx.dns.is_ipv4_only());
        assert_eq!(flushes.load(Ordering::SeqCst), 1);

        // Transition false -> true must flip back to ipv4_only=true before flushing again.
        let flushes_clone = Arc::clone(&flushes);
        let ipv4_only_seen_at_flush = Arc::new(AtomicBool::new(false));
        let ipv4_only_seen_clone = Arc::clone(&ipv4_only_seen_at_flush);
        let dns_ref = &ctx.dns;
        let changed = desktop_tun::sync_tun_dns_ipv4_only_if_changed(
            dns_ref,
            true,
            false,
            false,
            move || async move {
                ipv4_only_seen_clone.store(dns_ref.is_ipv4_only(), Ordering::SeqCst);
                flushes_clone.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert!(changed);
        assert!(ctx.dns.is_ipv4_only());
        assert!(ipv4_only_seen_at_flush.load(Ordering::SeqCst));
        assert_eq!(flushes.load(Ordering::SeqCst), 2);

        // Explicit --ipv4-only stays true even when IPv6 TUN is active; no flush.
        let flushes_clone = Arc::clone(&flushes);
        let changed = desktop_tun::sync_tun_dns_ipv4_only_if_changed(
            &ctx.dns,
            true,
            true,
            true,
            move || async move {
                flushes_clone.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert!(!changed);
        assert!(ctx.dns.is_ipv4_only());
        assert_eq!(flushes.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn apply_config_file_validates_regular_file_bounds_dns_split_apps_and_bypass_policy() {
        let dir = std::env::temp_dir().join(format!(
            "vdpi-main-apply-file-validate-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let valid_path = dir.join("valid.toml");
        std::fs::write(
            &valid_path,
            r#"
engine = "tun"
doh = true
dns_addr = "https://dns.nextdns.io/secret-token-123"
bypass_domains = ["*.local"]
include_domains = ["^discord\\.com$"]
split_tunnel_mode = "exclude"
split_tunnel_apps = ["discord.exe"]
"#,
        )
        .unwrap();
        let parsed = load_and_validate_apply_config_file(&valid_path).unwrap();
        assert_eq!(parsed.schema_version, Some(CONFIG_SCHEMA_VERSION));
        assert_eq!(parsed.engine, Some(EngineMode::Tun));
        assert_eq!(
            parsed.dns_addr.as_deref(),
            Some("https://dns.nextdns.io/secret-token-123")
        );
        assert_eq!(parsed.split_tunnel_mode, Some(SplitTunnelMode::Exclude));
        assert_eq!(
            parsed.split_tunnel_apps.as_deref(),
            Some(&["discord.exe".to_string()][..])
        );

        // Directories are rejected.
        assert!(load_and_validate_apply_config_file(&dir).is_err());

        // Oversized (> 1 MiB) files are rejected.
        let oversized_path = dir.join("oversized.toml");
        std::fs::write(
            &oversized_path,
            vec![b'#'; (MAX_APPLY_CONFIG_FILE_BYTES as usize) + 1],
        )
        .unwrap();
        assert!(load_and_validate_apply_config_file(&oversized_path).is_err());

        // Invalid DNS URL is rejected.
        let bad_dns_path = dir.join("bad_dns.toml");
        std::fs::write(&bad_dns_path, "dns_addr = \"http://insecure.example/dns\"\n").unwrap();
        assert!(load_and_validate_apply_config_file(&bad_dns_path).is_err());

        // Invalid split_tunnel_apps entry (control character) is rejected.
        let bad_apps_path = dir.join("bad_apps.toml");
        std::fs::write(&bad_apps_path, "split_tunnel_apps = [\"bad\\u0007app.exe\"]\n").unwrap();
        assert!(load_and_validate_apply_config_file(&bad_apps_path).is_err());

        // Invalid BypassPolicy regex is rejected.
        let bad_regex_path = dir.join("bad_regex.toml");
        std::fs::write(&bad_regex_path, "include_domains = [\"[unclosed\"]\n").unwrap();
        assert!(load_and_validate_apply_config_file(&bad_regex_path).is_err());

        // MAX_DOMAIN_ENTRIES (512) is enforced on both bypass_domains and include_domains.
        let at_limit_entries: String = (0..MAX_DOMAIN_ENTRIES)
            .map(|i| format!("\"host-{i}.example.org\""))
            .collect::<Vec<_>>()
            .join(", ");
        let at_limit_path = dir.join("domains_at_limit.toml");
        std::fs::write(
            &at_limit_path,
            format!(
                "bypass_domains = [{at_limit_entries}]\ninclude_domains = [{at_limit_entries}]\n"
            ),
        )
        .unwrap();
        assert!(load_and_validate_apply_config_file(&at_limit_path).is_ok());

        let over_limit_entries: String = (0..=MAX_DOMAIN_ENTRIES)
            .map(|i| format!("\"host-{i}.example.org\""))
            .collect::<Vec<_>>()
            .join(", ");
        let over_bypass_path = dir.join("bypass_over_limit.toml");
        std::fs::write(
            &over_bypass_path,
            format!("bypass_domains = [{over_limit_entries}]\n"),
        )
        .unwrap();
        assert!(load_and_validate_apply_config_file(&over_bypass_path).is_err());

        let over_include_path = dir.join("include_over_limit.toml");
        std::fs::write(
            &over_include_path,
            format!("include_domains = [{over_limit_entries}]\n"),
        )
        .unwrap();
        assert!(load_and_validate_apply_config_file(&over_include_path).is_err());

        // Parent traversal (`..`) in config file path is rejected.
        let traversal_path = dir.join("sub").join("..").join("valid.toml");
        assert!(load_and_validate_apply_config_file(&traversal_path).is_err());

        // Ownership policy allows current UID when unprivileged, and root or invoking UID when elevated.
        assert!(is_allowed_apply_file_owner(1000, 1000, None));
        assert!(!is_allowed_apply_file_owner(0, 1000, None));
        assert!(!is_allowed_apply_file_owner(2000, 1000, None));
        assert!(is_allowed_apply_file_owner(0, 0, None));
        assert!(!is_allowed_apply_file_owner(1000, 0, None));
        assert!(is_allowed_apply_file_owner(0, 0, Some(1000)));
        assert!(is_allowed_apply_file_owner(1000, 0, Some(1000)));
        assert!(!is_allowed_apply_file_owner(2000, 0, Some(1000)));

        // Symlinks (leaf and ancestor directories) are rejected.
        #[cfg(unix)]
        {
            let link_path = dir.join("link.toml");
            std::os::unix::fs::symlink(&valid_path, &link_path).unwrap();
            assert!(load_and_validate_apply_config_file(&link_path).is_err());

            let real_sub = dir.join("real_sub");
            std::fs::create_dir_all(&real_sub).unwrap();
            std::fs::write(real_sub.join("nested.toml"), "doh = true\n").unwrap();
            let linked_dir = dir.join("linked_sub");
            std::os::unix::fs::symlink(&real_sub, &linked_dir).unwrap();
            assert!(load_and_validate_apply_config_file(&linked_dir.join("nested.toml")).is_err());
        }
        #[cfg(windows)]
        {
            let link_path = dir.join("link.toml");
            if std::os::windows::fs::symlink_file(&valid_path, &link_path).is_ok() {
                assert!(load_and_validate_apply_config_file(&link_path).is_err());
            }
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_config_file_selects_target_saves_atomically_and_restarts_only_when_running() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = std::env::temp_dir().join(format!(
            "vdpi-main-apply-file-target-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let staged = dir.join("staged.toml");
        let sys_cfg = dir.join("system").join("config.toml");
        let user_cfg = dir.join("user").join("config.toml");
        let other_cfg = dir.join("other").join("custom.toml");
        std::fs::write(
            &staged,
            "engine = \"tun\"\ndns_addr = \"https://dns.nextdns.io/private-profile\"\n",
        )
        .unwrap();

        // System service running + elevated + --restart => writes system_path and restarts.
        let restarts = AtomicUsize::new(0);
        let (target, restarted) = apply_config_file_with(
            &staged,
            true,
            None,
            false,
            ServiceState::Running,
            true,
            true,
            &sys_cfg,
            &user_cfg,
            save_file_config_atomic,
            || {
                restarts.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(target, sys_cfg);
        assert!(restarted);
        assert_eq!(restarts.load(Ordering::SeqCst), 1);
        let (_, loaded_sys) = load_file_config(Some(&sys_cfg), true).unwrap();
        assert_eq!(
            loaded_sys.dns_addr.as_deref(),
            Some("https://dns.nextdns.io/private-profile")
        );

        // System service installed + not elevated => rejected before saving or restarting.
        let blocked = apply_config_file_with(
            &staged,
            true,
            None,
            false,
            ServiceState::Running,
            true,
            false,
            &sys_cfg,
            &user_cfg,
            |_, _| panic!("save_fn must not run when elevation is required"),
            || panic!("restart_fn must not run when elevation is required"),
        );
        assert!(blocked.is_err());

        // Not installed + --restart => writes user_path and does not restart.
        let (target, restarted) = apply_config_file_with(
            &staged,
            true,
            None,
            false,
            ServiceState::NotInstalled,
            false,
            false,
            &sys_cfg,
            &user_cfg,
            save_file_config_atomic,
            || panic!("restart_fn must not run when service is not running"),
        )
        .unwrap();
        assert_eq!(target, user_cfg);
        assert!(!restarted);
        assert!(user_cfg.is_file());

        // User-level service running + restart=false => writes user_path without restarting.
        let (target, restarted) = apply_config_file_with(
            &staged,
            false,
            None,
            false,
            ServiceState::Running,
            false,
            false,
            &sys_cfg,
            &user_cfg,
            save_file_config_atomic,
            || panic!("restart_fn must not run when restart=false"),
        )
        .unwrap();
        assert_eq!(target, user_cfg);
        assert!(!restarted);

        // User-level service running + restart=true => writes user_path and restarts.
        let user_restarts = AtomicUsize::new(0);
        let (target, restarted) = apply_config_file_with(
            &staged,
            true,
            None,
            false,
            ServiceState::Running,
            false,
            false,
            &sys_cfg,
            &user_cfg,
            save_file_config_atomic,
            || {
                user_restarts.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(target, user_cfg);
        assert!(restarted);
        assert_eq!(user_restarts.load(Ordering::SeqCst), 1);

        // Explicit unrelated --config path does not restart the OS service.
        let (target, restarted) = apply_config_file_with(
            &staged,
            true,
            Some(&other_cfg),
            false,
            ServiceState::Running,
            true,
            true,
            &sys_cfg,
            &user_cfg,
            save_file_config_atomic,
            || panic!("restart_fn must not run for unrelated explicit --config path"),
        )
        .unwrap();
        assert_eq!(target, other_cfg);
        assert!(!restarted);
        assert!(other_cfg.is_file());

        // Save succeeds but restart fails => tagged ApplyFileRestartError (exit code 2 in main).
        let restart_fail_cfg = dir.join("restart_fail").join("config.toml");
        let restart_err = apply_config_file_with(
            &staged,
            true,
            None,
            false,
            ServiceState::Running,
            true,
            true,
            &restart_fail_cfg,
            &user_cfg,
            save_file_config_atomic,
            || anyhow::bail!("simulated service restart failure"),
        )
        .unwrap_err();
        assert!(restart_fail_cfg.is_file());
        let tagged = restart_err
            .downcast_ref::<ApplyFileRestartError>()
            .expect("restart failure after save must be tagged with ApplyFileRestartError");
        assert_eq!(tagged.target, restart_fail_cfg);
        assert_eq!(EXIT_CODE_APPLY_RESTART_FAILED, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_show_includes_language_in_toml_and_json_and_resolves_i18n_pref() {
        let cfg = RuntimeConfig::default();
        let file_cfg_tr = FileConfig {
            language: Some("tr".to_string()),
            ..FileConfig::default()
        };

        let show_toml = render_config_toml(&build_config_show_file_config(&cfg, &file_cfg_tr));
        assert!(show_toml.contains("language = \"tr\""));
        let show_json = build_config_show_json(Some(Path::new("config.toml")), &cfg, &file_cfg_tr);
        assert_eq!(show_json["language"].as_str(), Some("tr"));

        let file_cfg_none = FileConfig::default();
        let show_toml_none =
            render_config_toml(&build_config_show_file_config(&cfg, &file_cfg_none));
        assert!(!show_toml_none.contains("language ="));
        let show_json_none = build_config_show_json(None, &cfg, &file_cfg_none);
        assert!(show_json_none["language"].is_null());

        assert_eq!(
            resolve_i18n_language_pref(&file_cfg_tr, false),
            Some(Some(vdpi::i18n::Lang::Tr))
        );
        let file_cfg_en = FileConfig {
            language: Some("en".to_string()),
            ..FileConfig::default()
        };
        assert_eq!(
            resolve_i18n_language_pref(&file_cfg_en, false),
            Some(Some(vdpi::i18n::Lang::En))
        );
        let file_cfg_auto = FileConfig {
            language: Some("auto".to_string()),
            ..FileConfig::default()
        };
        assert_eq!(resolve_i18n_language_pref(&file_cfg_auto, false), Some(None));
        assert_eq!(resolve_i18n_language_pref(&file_cfg_none, false), None);
        assert_eq!(resolve_i18n_language_pref(&file_cfg_none, true), Some(None));
    }

    #[test]
    fn startup_i18n_prefers_user_config_language_over_system_config_when_no_explicit_path() {
        let sys_cfg_en = FileConfig {
            language: Some("en".to_string()),
            ..FileConfig::default()
        };
        let sys_cfg_tr = FileConfig {
            language: Some("tr".to_string()),
            ..FileConfig::default()
        };
        let user_cfg_tr = FileConfig {
            language: Some("tr".to_string()),
            ..FileConfig::default()
        };
        let user_cfg_auto = FileConfig {
            language: Some("auto".to_string()),
            ..FileConfig::default()
        };
        let user_cfg_none = FileConfig::default();

        // When cli.config_path.is_none(), user_config language overrides system_config language.
        assert_eq!(
            resolve_startup_i18n_language_pref(&sys_cfg_en, Some(&user_cfg_tr), false),
            Some(Some(vdpi::i18n::Lang::Tr))
        );
        // Explicit "auto" in user_config overrides pinned language in system_config.
        assert_eq!(
            resolve_startup_i18n_language_pref(&sys_cfg_tr, Some(&user_cfg_auto), false),
            Some(None)
        );
        // Missing language in user_config falls back to system_config language.
        assert_eq!(
            resolve_startup_i18n_language_pref(&sys_cfg_tr, Some(&user_cfg_none), false),
            Some(Some(vdpi::i18n::Lang::Tr))
        );
        // Explicit --config path ignores user_config language.
        assert_eq!(
            resolve_startup_i18n_language_pref(&sys_cfg_en, Some(&user_cfg_tr), true),
            Some(Some(vdpi::i18n::Lang::En))
        );
        assert_eq!(
            resolve_startup_i18n_language_pref(&user_cfg_none, Some(&user_cfg_tr), true),
            Some(None)
        );
    }

    #[test]
    fn localized_control_center_notices_render_in_turkish_and_english() {
        let split = SplitTunnelConfig {
            mode: SplitTunnelMode::Exclude,
            apps: vec!["discord.exe".to_string(), "chrome.exe".to_string()],
        };
        {
            let _guard = vdpi::i18n::push_thread_lang(Some(vdpi::i18n::Lang::En));
            assert_eq!(
                format_split_tunnel_saved_notice(&split, true),
                "Split tunneling saved: Exclude (2 apps) (service restarted)"
            );
            assert_eq!(
                format_split_tunnel_saved_notice(&split, false),
                "Split tunneling saved: Exclude (2 apps)"
            );
        }
        {
            let _guard = vdpi::i18n::push_thread_lang(Some(vdpi::i18n::Lang::Tr));
            assert_eq!(
                format_split_tunnel_saved_notice(&split, true),
                "Bölünmüş tünel kaydedildi: Hariç tut (2 uygulama) (servis yeniden başlatıldı)"
            );
            assert_eq!(
                format_split_tunnel_saved_notice(&split, false),
                "Bölünmüş tünel kaydedildi: Hariç tut (2 uygulama)"
            );
            let corrupt = format_wintun_preflight_notice("SHA-256 verification failed");
            assert!(corrupt.contains("wintun.dll"));
            assert!(corrupt.contains("bozuk"));
            let missing = format_wintun_preflight_notice("wintun.dll not found");
            assert!(missing.contains("wintun.dll"));
            assert!(missing.contains("bulunamadı"));
        }
    }
}
