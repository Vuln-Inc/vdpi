use anyhow::Result;
use tokio::sync::watch;
use tracing::info;
use vdpi::config::{CliArgs, Command, RuntimeConfig};
use vdpi::desync::EngineContext;
use vdpi::platform::{platform_name, SystemProxySession};
use vdpi::server::{bind_listeners, serve_until_shutdown};
use vdpi::service::{
    clear_runtime_state, install_service, print_status, run_doctor, uninstall_service,
    write_runtime_state,
};

mod launcher;

fn main() -> Result<()> {
    raise_fd_limit();

    let args: Vec<_> = std::env::args_os().collect();
    let bare = args.len() == 1;
    let cli = CliArgs::parse_from_iter(args).unwrap_or_else(|e| e.exit());
    let mut command = cli.command.clone();
    let cfg = cli.into_runtime_config();
    init_tracing(&cfg);

    #[cfg(target_os = "windows")]
    if cfg.windows_service && matches!(command, Some(Command::Start) | None) {
        return vdpi::platform::windows_service::run_windows_service(cfg);
    }

    #[cfg(not(target_os = "windows"))]
    if cfg.windows_service {
        anyhow::bail!("--service is only supported on Windows");
    }

    if bare || matches!(command, Some(Command::Launcher)) {
        match launcher::choose(!bare)? {
            launcher::Choice::Run => {
                if !cfg.quiet {
                    launcher::print_run_notice();
                }
                command = Some(Command::Start);
            }
            launcher::Choice::Unattended => command = Some(Command::Start),
            launcher::Choice::Install => {
                let result = install_service(&cfg);
                launcher::install_finished(&result);
                return result;
            }
            launcher::Choice::Cancel => return Ok(()),
        }
    }

    match command {
        Some(Command::Install) => {
            install_service(&cfg)?;
            launcher::clear_preference();
            Ok(())
        }
        Some(Command::Launcher) => unreachable!("handled by launcher"),
        Some(Command::Uninstall) => uninstall_service(),
        Some(Command::Status) | Some(Command::Doctor) | Some(Command::Start) | None => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(async move {
                match command {
                    Some(Command::Status) => print_status(&cfg).await,
                    Some(Command::Doctor) => run_doctor(cfg).await,
                    Some(Command::Start) | None => run_daemon(cfg).await,
                    _ => unreachable!(),
                }
            })
        }
    }
}

async fn run_daemon(cfg: RuntimeConfig) -> Result<()> {
    let ctx = EngineContext::new(cfg.clone())?;
    let bound = bind_listeners(&ctx)?;

    let primary_addr = bound.primary_addr;
    let socks_addr = bound.socks_addr;
    write_runtime_state(primary_addr, socks_addr);

    let proxy_session = if cfg.system_proxy {
        Some(SystemProxySession::activate(
            primary_addr.ip(),
            primary_addr.port(),
            socks_addr.map(|a| a.port()),
            cfg.socks_system_proxy,
            cfg.env_proxy,
            &cfg.bypass_domains,
        )?)
    } else {
        None
    };

    if !cfg.quiet {
        print_startup_banner(
            &cfg,
            primary_addr,
            socks_addr,
            proxy_session.as_ref().map(|s| s.summary()),
        );
        info!(
            platform = platform_name(),
            mode = ?cfg.mode,
            chunk_size = cfg.chunk_size,
            doh = cfg.enable_doh,
            system_proxy = cfg.system_proxy,
            "vdpi engine active"
        );
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    if let Some(ref session) = proxy_session {
        let watchdog_session = session.clone();
        let mut watchdog_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = watchdog_rx.changed() => {
                        if *watchdog_rx.borrow() {
                            break;
                        }
                    }
                    _ = ticker.tick() => {
                        let s = watchdog_session.clone();
                        let _ = tokio::task::spawn_blocking(move || s.reconcile()).await;
                    }
                }
            }
        });
    }

    let server_task = tokio::spawn(serve_until_shutdown(bound, ctx, shutdown_rx));

    wait_for_shutdown_signal().await;
    info!("received shutdown signal; stopping vdpi cleanly");

    let _ = shutdown_tx.send(true);
    clear_runtime_state(std::process::id());
    if let Some(session) = proxy_session {
        session.deactivate();
    }

    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
    Ok(())
}

fn print_startup_banner(
    cfg: &RuntimeConfig,
    primary_addr: std::net::SocketAddr,
    socks_addr: Option<std::net::SocketAddr>,
    proxy_summary: Option<String>,
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
        proxy_summary.unwrap_or_else(|| "disabled (--no-system-proxy)".to_string())
    );
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

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to bind SIGTERM");
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to bind SIGINT");
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = sigint.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn raise_fd_limit() {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    unsafe {
        #[repr(C)]
        struct RLimit {
            rlim_cur: u64,
            rlim_max: u64,
        }
        extern "C" {
            fn getrlimit(resource: i32, rlp: *mut RLimit) -> i32;
            fn setrlimit(resource: i32, rlp: *const RLimit) -> i32;
        }
        #[cfg(target_os = "macos")]
        const RLIMIT_NOFILE: i32 = 8;
        #[cfg(target_os = "linux")]
        const RLIMIT_NOFILE: i32 = 7;

        let mut lim = RLimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if getrlimit(RLIMIT_NOFILE, &mut lim) == 0 {
            let target = 65536u64.min(lim.rlim_max);
            if lim.rlim_cur < target {
                lim.rlim_cur = target;
                let _ = setrlimit(RLIMIT_NOFILE, &lim);
            }
        }
    }
}
