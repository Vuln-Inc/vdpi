use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
use std::process::{Child, Command, Stdio};

use vdpi::config_file::{
    load_file_config_or_default, save_file_config_atomic, system_config_path, user_config_path,
    FileConfig, CONFIG_SCHEMA_VERSION,
};
use vdpi::service::{detect_service_state, installed_binary_path, vdpi_root_dir, ServiceState};
use vdpi::update::{
    check_latest_release, strip_windows_verbatim_prefix, ReleaseCheckResult, VersionRelation,
};
use vdpi_core::bypass::{BypassPolicy, IpNet};
use vdpi_core::config::{EngineMode, RuntimeConfig, VpnCoexistence};
use vdpi_core::dns::{
    effective_enable_doh, redact_dns_for_display, redact_urls_in_text, validate_custom_dns_input,
};

use crate::models::{
    ActionResultDto, DnsConfigUpdateDto, EngineModeDto, UpdateCheckPayloadDto, VpnCoexistenceDto,
};
use crate::sidecar::{self, SidecarOutcome};

const MAX_DOMAIN_ENTRY_LEN: usize = 255;
const MAX_DOMAIN_ENTRIES: usize = 512;
const MAX_EXTERNAL_URL_LEN: usize = 256;

const REPO_CANONICAL_URL: &str = "https://github.com/Vuln-Inc/vdpi";
const REPO_RELEASES_URL: &str = "https://github.com/Vuln-Inc/vdpi/releases";

const SIDECAR_TOGGLE_ELEVATED_TIMEOUT_SECS: u64 = 90;
const SIDECAR_TOGGLE_USER_TIMEOUT_SECS: u64 = 60;
const SIDECAR_ENGINE_TIMEOUT_SECS: u64 = 90;
const SIDECAR_INSTALL_TIMEOUT_SECS: u64 = 120;
const SIDECAR_UNINSTALL_TIMEOUT_SECS: u64 = 90;

const DISALLOWED_SCHEME_PREFIXES: &[&str] = &[
    "http",
    "https",
    "ftp",
    "ftps",
    "ws",
    "wss",
    "file",
    "data",
    "javascript",
    "mailto",
    "socks",
    "socks4",
    "socks5",
    "dns",
    "doh",
    "dot",
];

fn run_sidecar_cli(args: &[&str], elevated: bool, timeout_secs: u64) -> SidecarOutcome {
    if elevated {
        sidecar::run_vdpi_cli_elevated(args, timeout_secs)
    } else {
        sidecar::run_vdpi_cli(args, timeout_secs)
    }
}

fn action_ok(message: impl Into<String>, needs_restart: Option<bool>) -> ActionResultDto {
    ActionResultDto {
        ok: true,
        message: message.into(),
        needs_restart,
        cancelled: None,
    }
}

fn action_err(message: impl Into<String>, needs_restart: Option<bool>) -> ActionResultDto {
    ActionResultDto {
        ok: false,
        message: message.into(),
        needs_restart,
        cancelled: None,
    }
}

fn action_cancelled() -> ActionResultDto {
    ActionResultDto {
        ok: false,
        message: "Elevation was cancelled.".to_string(),
        needs_restart: None,
        cancelled: Some(true),
    }
}

const fn engine_mode_from_dto(mode: EngineModeDto) -> EngineMode {
    match mode {
        EngineModeDto::Tun => EngineMode::Tun,
        EngineModeDto::Proxy => EngineMode::Proxy,
    }
}

const fn vpn_coexistence_from_dto(mode: VpnCoexistenceDto) -> VpnCoexistence {
    match mode {
        VpnCoexistenceDto::AutoYield => VpnCoexistence::AutoYield,
        VpnCoexistenceDto::Warn => VpnCoexistence::Warn,
        VpnCoexistenceDto::Off => VpnCoexistence::Off,
    }
}

const fn engine_display_name(mode: EngineMode) -> &'static str {
    match mode {
        EngineMode::Tun => "TUN",
        EngineMode::Proxy => "Proxy",
    }
}

const fn engine_cli_arg(mode: EngineMode) -> &'static str {
    match mode {
        EngineMode::Tun => "tun",
        EngineMode::Proxy => "proxy",
    }
}

const fn engine_install_flag(mode: EngineMode) -> &'static str {
    match mode {
        EngineMode::Tun => "--tun",
        EngineMode::Proxy => "--proxy",
    }
}

fn redact_message(msg: &str) -> String {
    redact_urls_in_text(msg.trim())
}

fn redact_error(err: &anyhow::Error) -> String {
    redact_urls_in_text(&format!("{err:#}"))
}

fn redact_root_cause(err: &anyhow::Error) -> String {
    redact_urls_in_text(&err.root_cause().to_string())
}

fn is_permission_denied(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| io_err.kind() == ErrorKind::PermissionDenied)
    })
}

fn permission_denied_message() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "Administrator privileges are required to update settings."
    }
    #[cfg(target_os = "macos")]
    {
        "Administrator privileges are required to update settings."
    }
    #[cfg(target_os = "linux")]
    {
        "Root privileges are required to update settings."
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        "Elevated privileges are required to update settings."
    }
}

fn format_config_persistence_error(prefix: &str, err: &anyhow::Error) -> String {
    if is_permission_denied(err) {
        return permission_denied_message().to_string();
    }
    let detail = redact_root_cause(err);
    if detail.is_empty() {
        format!("{prefix}.")
    } else {
        format!("{prefix}: {detail}")
    }
}

fn is_system_service_installed() -> bool {
    #[cfg(target_os = "windows")]
    {
        detect_service_state() != ServiceState::NotInstalled
    }
    #[cfg(target_os = "macos")]
    {
        vdpi::service::launch_daemon_plist_path().exists()
    }
    #[cfg(target_os = "linux")]
    {
        vdpi::service::systemd_system_unit_path().exists()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

fn service_control_needs_elevation() -> bool {
    #[cfg(target_os = "windows")]
    {
        true
    }
    #[cfg(target_os = "macos")]
    {
        vdpi::service::launch_daemon_plist_path().exists()
    }
    #[cfg(target_os = "linux")]
    {
        vdpi::service::systemd_system_unit_path().exists()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

fn engine_switch_needs_elevation(target: EngineMode) -> bool {
    #[cfg(target_os = "windows")]
    {
        let _ = target;
        true
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        target == EngineMode::Tun || is_system_service_installed()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = target;
        false
    }
}

fn install_needs_elevation(target: EngineMode, system_service_installed: bool) -> bool {
    #[cfg(target_os = "windows")]
    {
        let _ = (target, system_service_installed);
        true
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        target == EngineMode::Tun || system_service_installed
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (target, system_service_installed);
        false
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn path_entry_exists(path: &Path) -> bool {
    // Use `symlink_metadata` rather than `Path::exists` so broken symlinks at
    // privileged system paths still trigger elevation during uninstall.
    fs::symlink_metadata(path).is_ok()
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn uninstall_needs_elevation_for_paths(paths: &[&Path]) -> bool {
    paths.iter().any(|path| path_entry_exists(path))
}

fn uninstall_needs_elevation() -> bool {
    #[cfg(target_os = "windows")]
    {
        true
    }
    #[cfg(target_os = "macos")]
    {
        let daemon_plist = vdpi::service::launch_daemon_plist_path();
        is_system_service_installed()
            || uninstall_needs_elevation_for_paths(&[
                Path::new("/usr/local/bin/vdpi"),
                daemon_plist.as_path(),
                Path::new("/Library/LaunchDaemons/com.vulninc.vdpi.plist"),
            ])
    }
    #[cfg(target_os = "linux")]
    {
        let systemd_unit = vdpi::service::systemd_system_unit_path();
        is_system_service_installed()
            || uninstall_needs_elevation_for_paths(&[
                Path::new("/usr/local/bin/vdpi"),
                systemd_unit.as_path(),
                Path::new("/etc/systemd/system/vdpi.service"),
            ])
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

fn default_engine_for_service_mode(system_service_installed: bool) -> EngineMode {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if system_service_installed {
        return EngineMode::Tun;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = system_service_installed;
    RuntimeConfig::default().engine
}

fn load_seed_file_config(
    primary_path: &Path,
    fallback_path: Option<&Path>,
    use_system: bool,
) -> anyhow::Result<(bool, FileConfig)> {
    match load_file_config_or_default(Some(primary_path), use_system)? {
        (Some(_), cfg) => Ok((true, cfg)),
        (None, _) => {
            if let Some(fallback) = fallback_path.filter(|fb| *fb != primary_path) {
                if let Ok((Some(_), cfg)) = load_file_config_or_default(Some(fallback), !use_system)
                {
                    return Ok((false, cfg));
                }
            }
            Ok((false, FileConfig::default()))
        }
    }
}

fn load_effective_runtime_config(use_system: bool) -> RuntimeConfig {
    let mut runtime = RuntimeConfig {
        engine: default_engine_for_service_mode(use_system),
        ..RuntimeConfig::default()
    };
    let sys_path = system_config_path();
    let user_path = user_config_path();
    let (primary, fallback) = if use_system {
        (sys_path.as_path(), None)
    } else {
        (user_path.as_path(), Some(sys_path.as_path()))
    };
    if let Ok((_, file_cfg)) = load_seed_file_config(primary, fallback, use_system) {
        file_cfg.apply_to_runtime(&mut runtime);
    }
    runtime
}

/// Validates, normalizes, and deduplicates a list of domain/wildcard/CIDR rules.
///
/// Rejects control characters, internal whitespace, URL schemes (such as `https://`
/// or `javascript:`), non-CIDR paths containing `/`, overly long entries, and lists
/// exceeding the maximum entry count. Empty/space-only entries are ignored.
pub fn sanitize_domain_list(domains: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::with_capacity(domains.len().min(MAX_DOMAIN_ENTRIES));
    let mut seen = HashSet::with_capacity(domains.len().min(MAX_DOMAIN_ENTRIES));

    for raw in domains {
        if raw.chars().any(char::is_control) {
            return Err("Domain entries cannot contain control characters.".to_string());
        }

        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.chars().any(char::is_whitespace) {
            return Err("Domain entries cannot contain whitespace.".to_string());
        }

        if trimmed.contains("://") {
            return Err(
                "Domain entries must not include a URL scheme (e.g. https://).".to_string(),
            );
        }

        if let Some((prefix, _)) = trimmed.split_once(':') {
            if DISALLOWED_SCHEME_PREFIXES
                .iter()
                .any(|scheme| prefix.eq_ignore_ascii_case(scheme))
            {
                return Err("Domain entries must not include a URL scheme.".to_string());
            }
        }

        if trimmed.contains('/') && IpNet::parse(trimmed).is_none() {
            return Err(
                "Domain entries cannot contain paths unless using valid CIDR notation (e.g. 203.0.113.0/24)."
                    .to_string(),
            );
        }

        if trimmed.len() > MAX_DOMAIN_ENTRY_LEN {
            return Err(format!(
                "Domain entry exceeds maximum length of {MAX_DOMAIN_ENTRY_LEN} characters."
            ));
        }

        let normalized = trimmed.to_ascii_lowercase();
        if seen.insert(normalized.clone()) {
            if out.len() >= MAX_DOMAIN_ENTRIES {
                return Err(format!(
                    "Domain list exceeds maximum of {MAX_DOMAIN_ENTRIES} entries."
                ));
            }
            out.push(normalized);
        }
    }

    Ok(out)
}

fn toggle_protection_with<FRun>(
    connect: bool,
    needs_elevation: bool,
    run_cli: FRun,
) -> ActionResultDto
where
    FRun: FnOnce(&[&str], bool) -> SidecarOutcome,
{
    let arg = if connect { "resume" } else { "pause" };
    match run_cli(&[arg], needs_elevation) {
        SidecarOutcome::Ok(_) => action_ok(
            if connect {
                "Protection enabled."
            } else {
                "Protection paused."
            },
            None,
        ),
        SidecarOutcome::SavedNeedsRestart(msg) => {
            let detail = redact_message(&msg);
            let message = if detail.is_empty() {
                "Settings saved. Restart protection to apply changes.".to_string()
            } else {
                detail
            };
            action_ok(message, Some(true))
        }
        SidecarOutcome::Cancelled => action_cancelled(),
        SidecarOutcome::Err(err) => {
            let verb = if connect { "enable" } else { "pause" };
            action_err(
                format!("Failed to {verb} protection: {}", redact_message(&err)),
                None,
            )
        }
    }
}

/// Enables (`connect = true`) or pauses (`connect = false`) the background `vdpi`
/// service by invoking the `vdpi` CLI sidecar (`resume` or `pause`), elevating
/// only when controlling a system-scoped service.
pub fn toggle_protection(connect: bool) -> ActionResultDto {
    let elevated = service_control_needs_elevation();
    let timeout = if elevated {
        SIDECAR_TOGGLE_ELEVATED_TIMEOUT_SECS
    } else {
        SIDECAR_TOGGLE_USER_TIMEOUT_SECS
    };
    toggle_protection_with(connect, elevated, |args, need_elev| {
        run_sidecar_cli(args, need_elev, timeout)
    })
}

fn switch_engine_with<FDetect, FRun>(
    engine: EngineModeDto,
    user_cfg_path: &Path,
    fallback_cfg_path: Option<&Path>,
    needs_elevation: bool,
    detect_service: FDetect,
    run_cli: FRun,
) -> ActionResultDto
where
    FDetect: FnOnce() -> ServiceState,
    FRun: FnOnce(&[&str], bool) -> SidecarOutcome,
{
    let target = engine_mode_from_dto(engine);
    let label = engine_display_name(target);
    let cli_mode = engine_cli_arg(target);
    let service_state = detect_service();

    if service_state != ServiceState::NotInstalled {
        return match run_cli(&["engine", cli_mode], needs_elevation) {
            SidecarOutcome::Ok(_) => {
                let message = if service_state == ServiceState::Running {
                    format!("Switched engine to {label} mode and restarted background service.")
                } else {
                    format!(
                        "Switched engine to {label} mode. It will take effect when protection is enabled."
                    )
                };
                action_ok(message, Some(false))
            }
            SidecarOutcome::SavedNeedsRestart(msg) => {
                let detail = redact_message(&msg);
                let message = if detail.is_empty() {
                    format!(
                        "Switched engine to {label} mode, but failed to restart the background service. Restart protection to apply changes."
                    )
                } else {
                    format!(
                        "Switched engine to {label} mode, but failed to restart the background service: {detail}"
                    )
                };
                action_ok(message, Some(true))
            }
            SidecarOutcome::Cancelled => action_cancelled(),
            SidecarOutcome::Err(err) => action_err(
                format!(
                    "Failed to switch engine to {label} mode: {}",
                    redact_message(&err)
                ),
                None,
            ),
        };
    }

    let mut file_cfg = match load_seed_file_config(user_cfg_path, fallback_cfg_path, false) {
        Ok((_, cfg)) => cfg,
        Err(err) => {
            return action_err(
                format_config_persistence_error(
                    "Failed to read configuration before switching engine",
                    &err,
                ),
                None,
            );
        }
    };
    file_cfg.schema_version = Some(CONFIG_SCHEMA_VERSION);
    file_cfg.engine = Some(target);

    match save_file_config_atomic(user_cfg_path, &file_cfg) {
        Ok(()) => action_ok(
            format!(
                "Saved {label} mode. Background service is not installed yet; install the service to activate it."
            ),
            None,
        ),
        Err(err) => action_err(
            format_config_persistence_error(&format!("Failed to save {label} mode"), &err),
            None,
        ),
    }
}

/// Switches the active transport engine (`TUN` or `Proxy`).
///
/// When the background service is installed, delegates to the `vdpi` CLI sidecar
/// (`engine tun|proxy`). Otherwise persists atomically to `config.toml`.
pub fn switch_engine(engine: EngineModeDto) -> ActionResultDto {
    let target = engine_mode_from_dto(engine);
    let user_cfg_path = user_config_path();
    let sys_cfg_path = system_config_path();
    let fallback = (sys_cfg_path != user_cfg_path).then_some(sys_cfg_path.as_path());
    let elevated = engine_switch_needs_elevation(target);
    switch_engine_with(
        engine,
        &user_cfg_path,
        fallback,
        elevated,
        detect_service_state,
        |args, need_elev| run_sidecar_cli(args, need_elev, SIDECAR_ENGINE_TIMEOUT_SECS),
    )
}

fn normalized_domain_list_lossy(domains: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(domains.len());
    let mut seen = HashSet::with_capacity(domains.len());
    for raw in domains {
        let normalized = raw.trim().to_ascii_lowercase();
        if !normalized.is_empty() && seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }
    out
}

fn save_dns_and_rules_with<FDetect, FApplySystem>(
    update: DnsConfigUpdateDto,
    primary_config_path: &Path,
    fallback_config_path: Option<&Path>,
    use_system_config: bool,
    detect_service: FDetect,
    apply_system_config: FApplySystem,
) -> ActionResultDto
where
    FDetect: FnOnce() -> ServiceState,
    FApplySystem: FnOnce(&FileConfig, bool, bool) -> SidecarOutcome,
{
    let validated_dns = match validate_custom_dns_input(&update.dns_addr) {
        Ok(dns) => dns,
        Err(msg) => {
            return action_err(redact_urls_in_text(&msg), None);
        }
    };

    let bypass_domains = match sanitize_domain_list(&update.bypass_domains) {
        Ok(list) => list,
        Err(msg) => {
            return action_err(format!("Invalid bypass domains: {msg}"), None);
        }
    };

    let include_domains = match sanitize_domain_list(&update.include_domains) {
        Ok(list) => list,
        Err(msg) => {
            return action_err(format!("Invalid include domains: {msg}"), None);
        }
    };

    if let Err(err) = BypassPolicy::new(&bypass_domains, &include_domains) {
        return action_err(format!("Invalid domain rule: {}", redact_error(&err)), None);
    }

    let effective_doh = effective_enable_doh(&validated_dns, update.doh_enabled);
    let new_vpn_coexistence = vpn_coexistence_from_dto(update.vpn_coexistence);
    let redacted_dns = redact_dns_for_display(&validated_dns);

    let service_state = detect_service();
    let service_installed = service_state != ServiceState::NotInstalled;
    let service_running = service_state == ServiceState::Running;

    let (seeded_from_primary, mut file_cfg) =
        match load_seed_file_config(primary_config_path, fallback_config_path, use_system_config) {
            Ok(loaded) => loaded,
            Err(err) => {
                return action_err(
                    format_config_persistence_error("Failed to load existing configuration", &err),
                    None,
                );
            }
        };

    let mut prev_runtime = RuntimeConfig::default();
    file_cfg.apply_to_runtime(&mut prev_runtime);
    let prev_dns = validate_custom_dns_input(&prev_runtime.dns_addr)
        .unwrap_or_else(|_| prev_runtime.dns_addr.clone());
    let prev_effective_doh = effective_enable_doh(&prev_dns, prev_runtime.enable_doh);
    let prev_bypass = normalized_domain_list_lossy(&prev_runtime.bypass_domains);
    let prev_include = normalized_domain_list_lossy(&prev_runtime.patterns);

    let dns_changed = prev_dns != validated_dns;
    let doh_changed = effective_doh != prev_effective_doh;
    let other_rules_changed = doh_changed
        || prev_runtime.block_quic != update.block_quic
        || prev_runtime.tun_ipv6 != update.tun_ipv6
        || prev_runtime.dns_ipv4_only != update.ipv4_only
        || prev_runtime.vpn_coexistence != new_vpn_coexistence
        || prev_bypass != bypass_domains
        || prev_include != include_domains;
    let anything_changed = dns_changed || other_rules_changed;

    file_cfg.schema_version = Some(CONFIG_SCHEMA_VERSION);
    file_cfg.dns_addr = Some(validated_dns);
    file_cfg.doh = Some(effective_doh);
    file_cfg.block_quic = Some(update.block_quic);
    file_cfg.tun_ipv6 = Some(update.tun_ipv6);
    file_cfg.ipv4_only = Some(update.ipv4_only);
    file_cfg.vpn_coexistence = Some(new_vpn_coexistence);
    file_cfg.bypass_domains = Some(bypass_domains);
    file_cfg.include_domains = Some(include_domains);

    if !anything_changed && seeded_from_primary {
        return action_ok(
            "DNS and routing settings are already up to date.",
            Some(false),
        );
    }

    // When a system-scoped service is installed, apply ALL changes atomically via a
    // restricted temporary config file through the elevated sidecar so secret DoH URLs
    // never appear on argv and non-DNS rule edits never hit PermissionDenied.
    if service_installed && use_system_config {
        return match apply_system_config(&file_cfg, true, service_running) {
            SidecarOutcome::Ok(_) => {
                let message = if service_running {
                    format!(
                        "Saved DNS ({redacted_dns}) and routing rules, and restarted background service."
                    )
                } else {
                    format!("Saved DNS ({redacted_dns}) and routing rules.")
                };
                action_ok(message, Some(false))
            }
            SidecarOutcome::SavedNeedsRestart(msg) => {
                let detail = redact_message(&msg);
                let message = if detail.is_empty() {
                    format!(
                        "Saved DNS ({redacted_dns}) and routing rules, but failed to restart the background service. Restart protection to apply changes."
                    )
                } else {
                    format!(
                        "Saved DNS ({redacted_dns}) and routing rules, but failed to restart the background service: {detail}"
                    )
                };
                ActionResultDto {
                    ok: true,
                    message,
                    needs_restart: Some(true),
                    cancelled: None,
                }
            }
            SidecarOutcome::Cancelled => action_cancelled(),
            SidecarOutcome::Err(err) => action_err(
                format!(
                    "Failed to save DNS and routing settings: {}",
                    redact_message(&err)
                ),
                None,
            ),
        };
    }

    if let Err(err) = save_file_config_atomic(primary_config_path, &file_cfg) {
        return action_err(
            format_config_persistence_error("Failed to save DNS and routing settings", &err),
            None,
        );
    }

    let needs_restart = service_running && anything_changed;
    let message = if needs_restart {
        format!(
            "Saved DNS ({redacted_dns}) and routing rules. Restart protection to apply changes."
        )
    } else if !anything_changed {
        "DNS and routing settings are already up to date.".to_string()
    } else {
        format!("Saved DNS ({redacted_dns}) and routing rules.")
    };

    action_ok(message, Some(needs_restart))
}

/// Validates DNS and routing rules, seeds from the active config fallback order,
/// and applies changes either via [`sidecar::apply_config_via_temp_file`] (when a
/// system-scoped service is installed) or atomically to the user's `config.toml`.
pub fn save_dns_and_rules(update: DnsConfigUpdateDto) -> ActionResultDto {
    let use_system = is_system_service_installed();
    let sys_path = system_config_path();
    let user_path = user_config_path();
    let (primary, fallback) = if use_system {
        (sys_path.as_path(), None)
    } else {
        let fb = (sys_path != user_path).then_some(sys_path.as_path());
        (user_path.as_path(), fb)
    };
    save_dns_and_rules_with(
        update,
        primary,
        fallback,
        use_system,
        detect_service_state,
        sidecar::apply_config_via_temp_file,
    )
}

fn install_background_service_with<FRun>(
    engine: EngineMode,
    needs_elevation: bool,
    run_cli: FRun,
) -> ActionResultDto
where
    FRun: FnOnce(&[&str], bool) -> SidecarOutcome,
{
    let flag = engine_install_flag(engine);
    match run_cli(&["install", flag], needs_elevation) {
        SidecarOutcome::Ok(_) => action_ok(
            format!(
                "Installed and started vdpi background service ({} mode).",
                engine_display_name(engine)
            ),
            Some(false),
        ),
        SidecarOutcome::SavedNeedsRestart(msg) => {
            let detail = redact_message(&msg);
            let message = if detail.is_empty() {
                format!(
                    "Installed vdpi background service ({} mode), but failed to restart the background service. Restart protection to apply changes.",
                    engine_display_name(engine)
                )
            } else {
                format!(
                    "Installed vdpi background service ({} mode), but failed to restart the background service: {detail}",
                    engine_display_name(engine)
                )
            };
            action_ok(message, Some(true))
        }
        SidecarOutcome::Cancelled => action_cancelled(),
        SidecarOutcome::Err(err) => action_err(
            format!(
                "Failed to install background service: {}",
                redact_message(&err)
            ),
            None,
        ),
    }
}

/// Installs and starts the OS background `vdpi` service via the real `vdpi` CLI
/// sidecar (`install --tun` or `install --proxy`) so SCM/launchd/systemd always
/// registers the `vdpi` engine binary rather than `vdpi-desktop`.
pub fn install_background_service() -> ActionResultDto {
    let use_system = is_system_service_installed();
    let cfg = load_effective_runtime_config(use_system);
    let elevated = install_needs_elevation(cfg.engine, use_system);
    install_background_service_with(cfg.engine, elevated, |args, need_elev| {
        run_sidecar_cli(args, need_elev, SIDECAR_INSTALL_TIMEOUT_SECS)
    })
}

fn uninstall_background_service_with<FRun>(needs_elevation: bool, run_cli: FRun) -> ActionResultDto
where
    FRun: FnOnce(&[&str], bool) -> SidecarOutcome,
{
    // Omitting `--purge` instructs `vdpi uninstall` to keep user/system `config.toml`
    // intact as promised in the desktop confirmation dialog.
    match run_cli(&["uninstall"], needs_elevation) {
        SidecarOutcome::Ok(_) => action_ok(
            "Uninstalled vdpi background service and restored system proxy settings.",
            Some(false),
        ),
        SidecarOutcome::SavedNeedsRestart(msg) => {
            let detail = redact_message(&msg);
            let message = if detail.is_empty() {
                "Uninstalled vdpi background service. Restart protection if needed.".to_string()
            } else {
                detail
            };
            action_ok(message, Some(true))
        }
        SidecarOutcome::Cancelled => action_cancelled(),
        SidecarOutcome::Err(err) => action_err(
            format!(
                "Failed to uninstall background service: {}",
                redact_message(&err)
            ),
            None,
        ),
    }
}

/// Stops and uninstalls the OS background `vdpi` service via the `vdpi` CLI
/// sidecar while preserving persisted configuration files.
pub fn uninstall_background_service() -> ActionResultDto {
    let elevated = uninstall_needs_elevation();
    uninstall_background_service_with(elevated, |args, need_elev| {
        run_sidecar_cli(args, need_elev, SIDECAR_UNINSTALL_TIMEOUT_SECS)
    })
}

fn validate_external_url(raw: &str) -> Result<String, String> {
    if raw.chars().any(char::is_control) {
        return Err("External URL contains invalid characters.".to_string());
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("External URL cannot be empty.".to_string());
    }
    if trimmed.len() > MAX_EXTERNAL_URL_LEN {
        return Err("External URL exceeds maximum allowed length.".to_string());
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("External URL contains invalid characters.".to_string());
    }
    if trimmed.contains(['\\', '@', '?', '#', '%']) {
        return Err("Refusing to open disallowed external URL.".to_string());
    }

    let Some(rest) = trimmed.strip_prefix(REPO_CANONICAL_URL) else {
        return Err(
            "Refusing to open URL outside the official vdpi GitHub repository.".to_string(),
        );
    };

    if rest.is_empty() || rest == "/" {
        return Ok(REPO_CANONICAL_URL.to_string());
    }

    let Some(after_releases) = rest.strip_prefix("/releases") else {
        return Err(
            "Refusing to open URL outside the official vdpi GitHub repository or releases."
                .to_string(),
        );
    };

    if after_releases.is_empty() || after_releases == "/" {
        return Ok(REPO_RELEASES_URL.to_string());
    }

    if after_releases == "/latest" || after_releases == "/latest/" {
        return Ok(format!("{REPO_RELEASES_URL}/latest"));
    }

    let Some(tag_with_opt_slash) = after_releases.strip_prefix("/tag/") else {
        return Err("External URL contains an invalid release path.".to_string());
    };

    let tag = tag_with_opt_slash
        .strip_suffix('/')
        .unwrap_or(tag_with_opt_slash);
    if tag.is_empty() || tag == "." || tag == ".." || tag.contains('/') {
        return Err("External URL contains an invalid release path.".to_string());
    }
    if !tag
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'))
    {
        return Err("External URL contains invalid characters in release path.".to_string());
    }

    Ok(format!("{REPO_RELEASES_URL}/tag/{tag}"))
}

fn release_check_to_dto(res: ReleaseCheckResult) -> UpdateCheckPayloadDto {
    let release_url =
        validate_external_url(&res.release_url).unwrap_or_else(|_| REPO_RELEASES_URL.to_string());
    UpdateCheckPayloadDto {
        current_version: res.current_version,
        latest_version: res.latest_version,
        has_update: res.relation == VersionRelation::Newer,
        release_url,
        release_notes: res.release_notes,
    }
}

/// Queries GitHub Releases for the latest `vdpi` version and returns a
/// frontend-ready update payload with a validated release URL.
pub async fn check_for_updates() -> Result<UpdateCheckPayloadDto, String> {
    check_latest_release()
        .await
        .map(release_check_to_dto)
        .map_err(|err| redact_error(&err))
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
fn spawn_child_reaper(mut child: Child) {
    let _ = std::thread::Builder::new()
        .name("vdpi-os-launcher-reaper".to_string())
        .spawn(move || {
            let _ = child.wait();
        });
}

#[cfg(any(target_os = "linux", test))]
const LINUX_LAUNCHER_REMOVED_ENV_VARS: &[&str] = &[
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "LD_AUDIT",
    "APPDIR",
    "APPIMAGE",
    "GTK_PATH",
    "GIO_EXTRA_MODULES",
    "GIO_MODULE_DIR",
    "GDK_PIXBUF_MODULE_FILE",
    "GDK_PIXBUF_MODULEDIR",
    "GSETTINGS_SCHEMA_DIR",
    "GTK_IM_MODULE_FILE",
];

#[cfg(any(target_os = "linux", test))]
fn sanitize_linux_launcher_env(cmd: &mut std::process::Command) {
    for var in LINUX_LAUNCHER_REMOVED_ENV_VARS {
        cmd.env_remove(var);
    }
}

#[cfg(any(
    target_os = "linux",
    all(
        test,
        any(target_os = "windows", target_os = "macos", target_os = "linux")
    )
))]
const XDG_OPEN_EARLY_EXIT_WAIT: std::time::Duration = std::time::Duration::from_millis(150);

#[cfg(any(
    target_os = "linux",
    all(
        test,
        any(target_os = "windows", target_os = "macos", target_os = "linux")
    )
))]
const XDG_OPEN_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(15);

#[cfg(any(
    target_os = "linux",
    all(
        test,
        any(target_os = "windows", target_os = "macos", target_os = "linux")
    )
))]
fn wait_briefly_or_detach_launcher_with_timeout(
    mut child: Child,
    failure_message: &str,
    wait_duration: std::time::Duration,
) -> Result<(), String> {
    let base = failure_message.trim_end_matches('.');
    let deadline = std::time::Instant::now() + wait_duration;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(());
                }
                return match status.code() {
                    Some(code) => Err(format!("{base} (exit code {code}).")),
                    None => Err(format!("{base}.")),
                };
            }
            Ok(None) => {
                let now = std::time::Instant::now();
                if now >= deadline {
                    spawn_child_reaper(child);
                    return Ok(());
                }
                let remaining = deadline.saturating_duration_since(now);
                std::thread::sleep(remaining.min(XDG_OPEN_POLL_INTERVAL));
            }
            Err(_) => {
                spawn_child_reaper(child);
                return Err(format!("{base}."));
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn wait_briefly_or_detach_launcher(child: Child, failure_message: &str) -> Result<(), String> {
    wait_briefly_or_detach_launcher_with_timeout(child, failure_message, XDG_OPEN_EARLY_EXIT_WAIT)
}

#[cfg(target_os = "windows")]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn spawn_os_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        let op = wide_null("open");
        let target = wide_null(url);
        let result = unsafe {
            ShellExecuteW(
                0,
                op.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        if result > 32 {
            Ok(())
        } else {
            Err("Failed to launch default web browser.".to_string())
        }
    }
    #[cfg(target_os = "macos")]
    {
        let child = Command::new("/usr/bin/open")
            .arg("--")
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "Failed to launch default web browser.".to_string())?;
        spawn_child_reaper(child);
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        // Standard `xdg-open` rejects `--` with exit code 1. `url` is strictly
        // validated to start with `https://github.com/Vuln-Inc/vdpi`, so it can
        // never be misinterpreted as a CLI flag.
        let mut cmd = Command::new("/usr/bin/xdg-open");
        sanitize_linux_launcher_env(&mut cmd);
        let child = cmd
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "Failed to launch default web browser.".to_string())?;
        wait_briefly_or_detach_launcher(child, "Failed to launch default web browser")
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = url;
        Err("Opening external URLs is not supported on this platform.".to_string())
    }
}

fn open_external_url_with<FOpen>(url: &str, open_fn: FOpen) -> ActionResultDto
where
    FOpen: FnOnce(&str) -> Result<(), String>,
{
    let safe_url = match validate_external_url(url) {
        Ok(valid) => valid,
        Err(message) => return action_err(message, None),
    };

    match open_fn(&safe_url) {
        Ok(()) => action_ok("Opened page in default browser.", None),
        Err(message) => action_err(redact_urls_in_text(&message), None),
    }
}

/// Strictly validates and opens an allowlisted `vdpi` GitHub URL
/// (`https://github.com/Vuln-Inc/vdpi`, `/releases`, `/releases/latest`, or
/// `/releases/tag/<tag>`) in the OS browser.
pub fn open_external_url(url: &str) -> ActionResultDto {
    open_external_url_with(url, spawn_os_browser)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AllowedDirectory {
    path: PathBuf,
    create_if_missing: bool,
}

#[cfg(any(target_os = "windows", test))]
fn validate_windows_path_syntax(raw: &str) -> Result<(), String> {
    if raw.is_empty() {
        return Err("Directory path cannot be empty.".to_string());
    }
    if raw.chars().any(char::is_control) {
        return Err("Directory path cannot contain control characters.".to_string());
    }
    let replaced = raw.replace('/', "\\");
    if replaced.starts_with(r"\\.\")
        || replaced.starts_with(r"\??\")
        || replaced.starts_with(r"\\?\")
    {
        return Err("Refusing to open a Windows device or verbatim namespace path.".to_string());
    }
    if replaced.starts_with(r"\\") {
        return Err("Refusing to open a UNC network path.".to_string());
    }
    let bytes = replaced.as_bytes();
    if !(bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\')
    {
        return Err("Directory path must be an absolute local drive path.".to_string());
    }
    // Reject Alternate Data Stream (ADS) colons anywhere after the drive letter prefix `X:`.
    if replaced[2..].contains(':') {
        return Err("Refusing to open path containing an alternate data stream colon.".to_string());
    }
    for seg in replaced[3..].split('\\') {
        if seg == ".." {
            return Err(
                "Refusing to open directory containing parent path traversal ('..').".to_string(),
            );
        }
        if seg.ends_with('.') && seg != "." {
            return Err("Directory path contains an invalid trailing dot segment.".to_string());
        }
        if seg.ends_with(' ') {
            return Err("Directory path contains an invalid trailing space segment.".to_string());
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn normalize_path_for_allowlist(path: &Path) -> Option<String> {
    if path.as_os_str().is_empty() {
        return None;
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return None;
    }
    let raw = path.to_str()?;
    validate_windows_path_syntax(raw).ok()?;

    let replaced = raw.replace('/', "\\");
    let drive = (replaced.as_bytes()[0] as char).to_ascii_lowercase();
    let prefix = format!("{drive}:\\");
    let rest = &replaced[3..];

    let mut parts = Vec::new();
    for seg in rest.split('\\') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return None;
        }
        parts.push(seg.to_ascii_lowercase());
    }

    if parts.is_empty() {
        Some(prefix)
    } else {
        Some(format!("{prefix}{}", parts.join("\\")))
    }
}

#[cfg(not(target_os = "windows"))]
fn normalize_path_for_allowlist(path: &Path) -> Option<String> {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return None;
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return None;
    }
    let raw = path.to_str()?;
    if raw.chars().any(char::is_control) {
        return None;
    }

    let mut parts = Vec::new();
    for seg in raw.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return None;
        }
        parts.push(seg);
    }

    Some(format!("/{}", parts.join("/")))
}

fn paths_match_allowlist(a: &Path, b: &Path) -> bool {
    let (Some(na), Some(nb)) = (
        normalize_path_for_allowlist(a),
        normalize_path_for_allowlist(b),
    ) else {
        return false;
    };
    na == nb
}

#[cfg(target_os = "windows")]
fn is_symlink_or_reparse(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    meta.file_type().is_symlink() || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

#[cfg(not(target_os = "windows"))]
fn is_symlink_or_reparse(meta: &fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn is_allowed_os_system_symlink_path(path: &Path, uid: u32, is_linux: bool) -> bool {
    if uid != 0 {
        return false;
    }
    let Some(raw) = path.to_str() else {
        return false;
    };
    if is_linux {
        matches!(raw, "/home" | "/usr/local" | "/var" | "/tmp" | "/etc")
    } else {
        matches!(raw, "/var" | "/tmp" | "/etc")
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn is_allowed_os_system_symlink(path: &Path, meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    is_allowed_os_system_symlink_path(path, meta.uid(), cfg!(target_os = "linux"))
}

fn verify_no_symlinks_in_path(path: &Path, allow_missing_tail: bool) -> Result<(), String> {
    let components: Vec<Component<'_>> = path.components().collect();
    let last_normal_idx = components
        .iter()
        .rposition(|c| matches!(c, Component::Normal(_)));
    let mut current = PathBuf::new();
    for (idx, comp) in components.iter().enumerate() {
        match comp {
            Component::Prefix(prefix) => {
                current.push(prefix.as_os_str());
            }
            Component::RootDir => {
                current.push(comp.as_os_str());
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(
                    "Refusing to open directory containing parent path traversal ('..')."
                        .to_string(),
                );
            }
            Component::Normal(part) => {
                current.push(part);
                match fs::symlink_metadata(&current) {
                    Ok(meta) => {
                        if is_symlink_or_reparse(&meta) {
                            #[cfg(any(target_os = "macos", target_os = "linux"))]
                            if Some(idx) != last_normal_idx
                                && is_allowed_os_system_symlink(&current, &meta)
                                && matches!(fs::metadata(&current), Ok(target) if target.is_dir())
                            {
                                continue;
                            }
                            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                            let _ = (idx, last_normal_idx);
                            return Err(
                                "Refusing to open directory containing a symbolic link or reparse point."
                                    .to_string(),
                            );
                        }
                    }
                    Err(err) if err.kind() == ErrorKind::NotFound => {
                        if allow_missing_tail {
                            return Ok(());
                        }
                        return Err("Directory does not exist yet.".to_string());
                    }
                    Err(_) => {
                        return Err("Failed to inspect target directory.".to_string());
                    }
                }
            }
        }
    }
    Ok(())
}

fn push_allowed_dir(dirs: &mut Vec<AllowedDirectory>, path: PathBuf, create_if_missing: bool) {
    let clean = strip_windows_verbatim_prefix(&path);
    if clean.as_os_str().is_empty() {
        return;
    }
    if let Some(existing) = dirs
        .iter_mut()
        .find(|entry| paths_match_allowlist(&entry.path, &clean))
    {
        if create_if_missing {
            existing.create_if_missing = true;
        }
        return;
    }
    dirs.push(AllowedDirectory {
        path: clean,
        create_if_missing,
    });
}

#[cfg(any(target_os = "macos", test))]
fn map_macos_var_log_alias(path: &Path) -> PathBuf {
    let Some(raw) = path.to_str() else {
        return path.to_path_buf();
    };
    if !raw.starts_with('/') || raw.chars().any(char::is_control) {
        return path.to_path_buf();
    }
    let mut parts = Vec::new();
    for seg in raw.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return path.to_path_buf();
        }
        parts.push(seg);
    }
    if parts.as_slice() == ["var", "log"] {
        PathBuf::from("/private/var/log")
    } else {
        path.to_path_buf()
    }
}

fn create_user_logs_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
    }
}

fn allowed_vdpi_directories() -> Vec<AllowedDirectory> {
    let mut dirs = Vec::new();
    let user_cfg_dir = user_config_path()
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf);

    if let Some(ref parent) = user_cfg_dir {
        push_allowed_dir(&mut dirs, parent.clone(), false);
    }
    if let Some(parent) = system_config_path()
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        push_allowed_dir(&mut dirs, parent.to_path_buf(), false);
    }
    if let Ok(root) = vdpi_root_dir() {
        // On Unix, `vdpi_root_dir()` is `~/.vdpi`, so `~/.vdpi/logs` is user-writable
        // and safe to create on demand if logs have not been written yet.
        let create_logs_if_missing = cfg!(not(target_os = "windows"));
        push_allowed_dir(&mut dirs, root.join("logs"), create_logs_if_missing);
    }
    if let Some(ref parent) = user_cfg_dir {
        push_allowed_dir(&mut dirs, parent.join("logs"), true);
    }
    #[cfg(target_os = "macos")]
    {
        push_allowed_dir(&mut dirs, PathBuf::from("/private/var/log"), false);
    }
    #[cfg(target_os = "linux")]
    {
        push_allowed_dir(&mut dirs, PathBuf::from("/var/log/vdpi"), false);
        push_allowed_dir(&mut dirs, PathBuf::from("/var/log"), false);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent().filter(|p| !p.as_os_str().is_empty()) {
            push_allowed_dir(&mut dirs, parent.to_path_buf(), false);
        }
    }
    if let Ok(installed_bin) = installed_binary_path() {
        if let Some(parent) = installed_bin
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            push_allowed_dir(&mut dirs, parent.to_path_buf(), false);
        }
    }
    dirs
}

fn resolve_allowlisted_directory(
    requested: &Path,
    allowed_dirs: &[AllowedDirectory],
) -> Result<PathBuf, String> {
    if requested.as_os_str().is_empty() {
        return Err("Directory path cannot be empty.".to_string());
    }
    let Some(raw) = requested.to_str() else {
        return Err("Directory path contains invalid UTF-8.".to_string());
    };
    if raw.chars().any(char::is_control) {
        return Err("Directory path cannot contain control characters.".to_string());
    }
    if requested
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(
            "Refusing to open directory containing parent path traversal ('..').".to_string(),
        );
    }

    #[cfg(target_os = "windows")]
    validate_windows_path_syntax(raw)?;

    #[cfg(target_os = "macos")]
    let effective_requested = map_macos_var_log_alias(requested);
    #[cfg(not(target_os = "macos"))]
    let effective_requested = requested.to_path_buf();

    let Some(matched) = allowed_dirs
        .iter()
        .find(|allowed| {
            #[cfg(target_os = "macos")]
            let allowed_path = map_macos_var_log_alias(&allowed.path);
            #[cfg(not(target_os = "macos"))]
            let allowed_path = allowed.path.clone();
            paths_match_allowlist(&effective_requested, &allowed_path)
        })
        .cloned()
    else {
        return Err("Refusing to open directory outside vdpi's allowed directories.".to_string());
    };

    #[cfg(target_os = "macos")]
    let target_path = map_macos_var_log_alias(&matched.path);
    #[cfg(not(target_os = "macos"))]
    let target_path = matched.path;

    #[cfg(target_os = "windows")]
    {
        let Some(matched_raw) = target_path.to_str() else {
            return Err("Target directory path contains invalid UTF-8.".to_string());
        };
        validate_windows_path_syntax(matched_raw)?;
    }

    verify_no_symlinks_in_path(&target_path, matched.create_if_missing)?;

    match fs::symlink_metadata(&target_path) {
        Ok(meta) => {
            if is_symlink_or_reparse(&meta) {
                return Err(
                    "Refusing to open a symbolic link or reparse point directory.".to_string(),
                );
            }
            if !meta.is_dir() {
                return Err("Target path is not a directory.".to_string());
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            if matched.create_if_missing {
                create_user_logs_dir(&target_path)
                    .map_err(|_| "Failed to create logs directory.".to_string())?;
                verify_no_symlinks_in_path(&target_path, false)?;
                let meta = fs::symlink_metadata(&target_path)
                    .map_err(|_| "Failed to inspect target directory.".to_string())?;
                if is_symlink_or_reparse(&meta) || !meta.is_dir() {
                    return Err("Target path is not a valid directory.".to_string());
                }
            } else {
                return Err("Directory does not exist yet.".to_string());
            }
        }
        Err(_) => {
            return Err("Failed to inspect target directory.".to_string());
        }
    }

    Ok(target_path)
}

#[cfg(target_os = "windows")]
fn windows_explorer_path() -> Result<PathBuf, String> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;

    let mut buf = vec![0u16; 260];
    let len = unsafe { GetWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if len == 0 {
        return Err("Failed to locate the Windows system directory.".to_string());
    }
    if len >= buf.len() {
        buf.resize(len + 1, 0);
        let len2 = unsafe { GetWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if len2 == 0 || len2 >= buf.len() {
            return Err("Failed to locate the Windows system directory.".to_string());
        }
        buf.truncate(len2);
    } else {
        buf.truncate(len);
    }
    let explorer = PathBuf::from(OsString::from_wide(&buf)).join("explorer.exe");
    if !explorer.is_file() {
        return Err("File Explorer executable could not be found.".to_string());
    }
    Ok(explorer)
}

fn spawn_os_file_manager(dir: &Path) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let explorer = windows_explorer_path()?;
        let child = Command::new(&explorer)
            .arg(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "Failed to open folder in File Explorer.".to_string())?;
        spawn_child_reaper(child);
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let child = Command::new("/usr/bin/open")
            .arg("--")
            .arg(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "Failed to open folder in Finder.".to_string())?;
        spawn_child_reaper(child);
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        // Standard `xdg-open` rejects `--` with exit code 1. `dir` is strictly
        // validated to be an absolute path starting with `/`, so it can never be
        // misinterpreted as a CLI flag.
        let mut cmd = Command::new("/usr/bin/xdg-open");
        sanitize_linux_launcher_env(&mut cmd);
        let child = cmd
            .arg(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "Failed to open folder in file manager.".to_string())?;
        wait_briefly_or_detach_launcher(child, "Failed to open folder in file manager")
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = dir;
        Err("Opening directories in the OS file manager is not supported on this platform."
            .to_string())
    }
}

fn open_directory_in_os_with<FOpen>(
    path: &Path,
    allowed_dirs: &[AllowedDirectory],
    open_fn: FOpen,
) -> ActionResultDto
where
    FOpen: FnOnce(&Path) -> Result<(), String>,
{
    let target = match resolve_allowlisted_directory(path, allowed_dirs) {
        Ok(dir) => dir,
        Err(message) => return action_err(message, None),
    };

    match open_fn(&target) {
        Ok(()) => action_ok("Opened folder.", None),
        Err(message) => action_err(redact_urls_in_text(&message), None),
    }
}

/// Opens an allowlisted `vdpi` directory (config, logs, or app/install folder)
/// in the host OS file manager using absolute system binaries, after walking
/// every path component to reject symlinks, reparse points, and device paths.
pub fn open_directory_in_os(path: &Path) -> ActionResultDto {
    let allowed = allowed_vdpi_directories();
    open_directory_in_os_with(path, &allowed, spawn_os_file_manager)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::{AtomicU64, Ordering};
    use vdpi::config_file::load_file_config;

    static TEMP_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TempDirGuard(PathBuf);

    impl TempDirGuard {
        fn new(label: &str) -> Self {
            let seq = TEMP_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
            #[cfg(not(target_os = "windows"))]
            let base =
                fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
            #[cfg(target_os = "windows")]
            let base = strip_windows_verbatim_prefix(&std::env::temp_dir());

            let dir = base.join(format!(
                "vdpi-desktop-actions-test-{label}-{}-{seq}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).expect("create temp test dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn config_path(&self) -> PathBuf {
            self.0.join("config.toml")
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn base_dns_update() -> DnsConfigUpdateDto {
        DnsConfigUpdateDto {
            dns_addr: "1.1.1.1".to_string(),
            doh_enabled: true,
            block_quic: true,
            tun_ipv6: false,
            ipv4_only: false,
            vpn_coexistence: VpnCoexistenceDto::AutoYield,
            bypass_domains: vec![],
            include_domains: vec![],
        }
    }

    #[test]
    fn sanitize_domain_list_accepts_domains_wildcards_ips_and_cidrs() {
        let input = vec![
            "  Example.COM  ".to_string(),
            "*.Sub.Example.org".to_string(),
            ".legacy.example.net".to_string(),
            "example.com".to_string(),
            "   ".to_string(),
            "".to_string(),
            "203.0.113.0/24".to_string(),
            "2001:DB8::/32".to_string(),
            "1.1.1.1".to_string(),
        ];

        let sanitized = sanitize_domain_list(&input).expect("valid domain list");
        assert_eq!(
            sanitized,
            vec![
                "example.com",
                "*.sub.example.org",
                ".legacy.example.net",
                "203.0.113.0/24",
                "2001:db8::/32",
                "1.1.1.1",
            ]
        );
    }

    #[test]
    fn sanitize_domain_list_rejects_whitespace_control_chars_schemes_and_paths() {
        let err = sanitize_domain_list(&["bad domain.com".to_string()])
            .expect_err("whitespace must be rejected");
        assert!(err.contains("whitespace"));

        for bad in [
            "bad\ndomain.com",
            "bad\rdomain.com",
            "bad\tdomain.com",
            "bad\0domain.com",
            "\x1bexample.com",
        ] {
            let err = sanitize_domain_list(&[bad.to_string()])
                .expect_err("control chars must be rejected");
            assert!(
                err.contains("control characters"),
                "unexpected err for {bad:?}: {err}"
            );
        }

        for bad in [
            "https://example.com",
            "http://example.com",
            "HTTPS://user:supersecret@dns.example.com/token123",
            "ftp://files.example.com",
            "javascript:alert(1)",
            "http:example.com",
            "data:text/plain,hello",
        ] {
            let err =
                sanitize_domain_list(&[bad.to_string()]).expect_err("scheme must be rejected");
            assert!(err.contains("scheme"), "unexpected err for {bad:?}: {err}");
            assert!(
                !err.contains("supersecret") && !err.contains("token123"),
                "error must not echo sensitive URL tokens: {err}"
            );
        }

        let err = sanitize_domain_list(&["example.com/secret/path".to_string()])
            .expect_err("path must be rejected");
        assert!(err.contains("CIDR"));
        assert!(!err.contains("secret"));

        let long = format!("{}.com", "a".repeat(MAX_DOMAIN_ENTRY_LEN));
        let err = sanitize_domain_list(&[long]).expect_err("oversized entry must be rejected");
        assert!(err.contains("maximum length"));

        let many: Vec<String> = (0..=MAX_DOMAIN_ENTRIES)
            .map(|i| format!("host{i}.example.com"))
            .collect();
        let err = sanitize_domain_list(&many).expect_err("excessive list must be rejected");
        assert!(err.contains("maximum"));
    }

    #[test]
    fn toggle_protection_uses_sidecar_maps_cancellation_and_redacts_urls() {
        let on = toggle_protection_with(true, true, |args, elevated| {
            assert_eq!(args, &["resume"]);
            assert!(elevated);
            SidecarOutcome::Ok(String::new())
        });
        assert!(on.ok);
        assert!(on.message.contains("enabled"));
        assert_eq!(on.cancelled, None);

        let off = toggle_protection_with(false, false, |args, elevated| {
            assert_eq!(args, &["pause"]);
            assert!(!elevated);
            SidecarOutcome::Ok(String::new())
        });
        assert!(off.ok);
        assert!(off.message.contains("paused"));
        assert_eq!(off.cancelled, None);

        let cancelled = toggle_protection_with(true, true, |_, _| SidecarOutcome::Cancelled);
        assert!(!cancelled.ok);
        assert_eq!(cancelled.message, "Elevation was cancelled.");
        assert_eq!(cancelled.needs_restart, None);
        assert_eq!(cancelled.cancelled, Some(true));

        let failed = toggle_protection_with(true, true, |_, _| {
            SidecarOutcome::Err(
                "DoH probe failed for https://alice:topsecret@dns.nextdns.io/abc123?key=xyz"
                    .to_string(),
            )
        });
        assert!(!failed.ok);
        assert_eq!(failed.cancelled, None);
        assert!(failed.message.contains("https://dns.nextdns.io"));
        assert!(!failed.message.contains("topsecret"));
        assert!(!failed.message.contains("abc123"));
        assert!(!failed.message.contains("key=xyz"));
    }

    #[test]
    fn switch_engine_delegates_to_sidecar_when_installed_and_persists_when_not_installed() {
        let dir = TempDirGuard::new("switch-engine");
        let user_cfg_path = dir.path().join("user.toml");
        let sys_cfg_path = dir.path().join("system.toml");

        // Seed fallback system config to verify fallback seeding when user config is absent.
        let seed = FileConfig {
            dns_addr: Some("9.9.9.9".to_string()),
            block_quic: Some(false),
            ..Default::default()
        };
        save_file_config_atomic(&sys_cfg_path, &seed).expect("seed fallback config");

        // Not installed -> seeds from fallback, writes user config, omits raw path from toast.
        let res_uninstalled = switch_engine_with(
            EngineModeDto::Tun,
            &user_cfg_path,
            Some(&sys_cfg_path),
            true,
            || ServiceState::NotInstalled,
            |_, _| unreachable!("service not installed"),
        );
        assert!(
            res_uninstalled.ok,
            "unexpected error: {}",
            res_uninstalled.message
        );
        assert!(res_uninstalled.message.contains("TUN"));
        assert!(res_uninstalled.message.contains("not installed"));
        assert!(
            !res_uninstalled
                .message
                .contains(&user_cfg_path.display().to_string()),
            "toast must not expose raw config path: {}",
            res_uninstalled.message
        );
        assert_eq!(res_uninstalled.needs_restart, None);

        let (_, reloaded) = load_file_config(Some(&user_cfg_path), false).expect("reload config");
        assert_eq!(reloaded.engine, Some(EngineMode::Tun));
        assert_eq!(reloaded.dns_addr.as_deref(), Some("9.9.9.9"));
        assert_eq!(reloaded.block_quic, Some(false));

        // Installed & running -> delegates to sidecar `engine proxy`.
        let called = Cell::new(false);
        let res_running = switch_engine_with(
            EngineModeDto::Proxy,
            &user_cfg_path,
            Some(&sys_cfg_path),
            true,
            || ServiceState::Running,
            |args, elevated| {
                called.set(true);
                assert_eq!(args, &["engine", "proxy"]);
                assert!(elevated);
                SidecarOutcome::Ok(String::new())
            },
        );
        assert!(called.get());
        assert!(res_running.ok);
        assert_eq!(res_running.needs_restart, Some(false));
        assert!(res_running.message.contains("Proxy"));

        // Elevation cancelled maps to `cancelled: Some(true)`.
        let res_cancelled = switch_engine_with(
            EngineModeDto::Tun,
            &user_cfg_path,
            None,
            true,
            || ServiceState::Running,
            |_, _| SidecarOutcome::Cancelled,
        );
        assert!(!res_cancelled.ok);
        assert_eq!(res_cancelled.message, "Elevation was cancelled.");
        assert_eq!(res_cancelled.cancelled, Some(true));

        // Error redacts embedded URLs.
        let res_err = switch_engine_with(
            EngineModeDto::Tun,
            &user_cfg_path,
            None,
            true,
            || ServiceState::Stopped,
            |_, _| {
                SidecarOutcome::Err(
                    "failed against https://user:pw@dns.example.com/secretpath".to_string(),
                )
            },
        );
        assert!(!res_err.ok);
        assert!(res_err.message.contains("https://dns.example.com"));
        assert!(!res_err.message.contains("secretpath"));
        assert!(!res_err.message.contains("pw"));
    }

    #[test]
    fn save_dns_and_rules_validates_seeds_applies_via_temp_file_and_tracks_restart() {
        let dir = TempDirGuard::new("save-dns");
        let cfg_path = dir.config_path();

        // Invalid DNS is rejected before touching disk or sidecar.
        let mut bad_dns = base_dns_update();
        bad_dns.dns_addr = "http://1.1.1.1/dns-query".to_string();
        let res = save_dns_and_rules_with(
            bad_dns,
            &cfg_path,
            None,
            false,
            || ServiceState::Running,
            |_, _, _| unreachable!("invalid DNS must not invoke sidecar"),
        );
        assert!(!res.ok);
        assert!(!cfg_path.exists());

        // Invalid domain list is rejected before touching disk.
        let mut bad_domain = base_dns_update();
        bad_domain.bypass_domains = vec!["https://example.com".to_string()];
        let res = save_dns_and_rules_with(
            bad_domain,
            &cfg_path,
            None,
            false,
            || ServiceState::Running,
            |_, _, _| unreachable!(),
        );
        assert!(!res.ok);
        assert!(res.message.contains("Invalid bypass domains"));
        assert!(!cfg_path.exists());

        // Invalid include regex is caught by BypassPolicy::new before touching disk.
        let mut bad_regex = base_dns_update();
        bad_regex.include_domains = vec!["[unclosed".to_string()];
        let res = save_dns_and_rules_with(
            bad_regex,
            &cfg_path,
            None,
            false,
            || ServiceState::Running,
            |_, _, _| unreachable!(),
        );
        assert!(!res.ok);
        assert!(res.message.contains("Invalid domain rule"));
        assert!(!cfg_path.exists());

        // Fallback seeding preserves unrelated engine field when user config doesn't exist yet.
        let fallback_sys = dir.path().join("fallback-system.toml");
        save_file_config_atomic(
            &fallback_sys,
            &FileConfig {
                engine: Some(EngineMode::Tun),
                ..Default::default()
            },
        )
        .expect("seed fallback config");

        let update_not_installed = DnsConfigUpdateDto {
            dns_addr: "https://dns.nextdns.io/mysecretprofile".to_string(),
            doh_enabled: false,
            block_quic: false,
            tun_ipv6: true,
            ipv4_only: true,
            vpn_coexistence: VpnCoexistenceDto::Warn,
            bypass_domains: vec!["  Example.COM ".to_string(), "*.corp.local".to_string()],
            include_domains: vec!["discord.com".to_string()],
        };
        let res = save_dns_and_rules_with(
            update_not_installed,
            &cfg_path,
            Some(&fallback_sys),
            false,
            || ServiceState::NotInstalled,
            |_, _, _| unreachable!("service not installed"),
        );
        assert!(res.ok, "expected save ok: {}", res.message);
        assert_eq!(res.needs_restart, Some(false));
        assert!(res.message.contains("https://dns.nextdns.io"));
        assert!(!res.message.contains("mysecretprofile"));
        assert!(!res.message.contains(&cfg_path.display().to_string()));

        let (_, reloaded) = load_file_config(Some(&cfg_path), false).expect("reload config");
        assert_eq!(reloaded.engine, Some(EngineMode::Tun));
        assert_eq!(
            reloaded.dns_addr.as_deref(),
            Some("https://dns.nextdns.io/mysecretprofile")
        );
        assert_eq!(reloaded.doh, Some(true));
        assert_eq!(reloaded.block_quic, Some(false));
        assert_eq!(reloaded.tun_ipv6, Some(true));
        assert_eq!(reloaded.ipv4_only, Some(true));
        assert_eq!(reloaded.vpn_coexistence, Some(VpnCoexistence::Warn));
        assert_eq!(
            reloaded.bypass_domains,
            Some(vec!["example.com".to_string(), "*.corp.local".to_string()])
        );
        assert_eq!(
            reloaded.include_domains,
            Some(vec!["discord.com".to_string()])
        );

        // User-scoped running service + rule change -> saves atomically, needs_restart = true.
        let update_rule_only = DnsConfigUpdateDto {
            dns_addr: "https://dns.nextdns.io/mysecretprofile".to_string(),
            doh_enabled: true,
            block_quic: true,
            tun_ipv6: true,
            ipv4_only: true,
            vpn_coexistence: VpnCoexistenceDto::Warn,
            bypass_domains: vec!["example.com".to_string(), "*.corp.local".to_string()],
            include_domains: vec!["discord.com".to_string()],
        };
        let res = save_dns_and_rules_with(
            update_rule_only.clone(),
            &cfg_path,
            None,
            false,
            || ServiceState::Running,
            |_, _, _| unreachable!("user-scoped service saves directly"),
        );
        assert!(res.ok);
        assert_eq!(res.needs_restart, Some(true));

        // Identical values on existing config -> no-op, no restart required.
        let res_noop = save_dns_and_rules_with(
            update_rule_only,
            &cfg_path,
            None,
            false,
            || ServiceState::Running,
            |_, _, _| unreachable!("nothing changed"),
        );
        assert!(res_noop.ok);
        assert_eq!(res_noop.needs_restart, Some(false));

        // System service installed: BOTH DNS and non-DNS rule edits apply via temp-file sidecar
        // (never direct write PermissionDenied and never secret DoH URLs on argv).
        let sys_dir = TempDirGuard::new("save-dns-sys");
        let sys_cfg_path = sys_dir.config_path();
        save_file_config_atomic(
            &sys_cfg_path,
            &FileConfig {
                engine: Some(EngineMode::Tun),
                dns_addr: Some("1.1.1.1".to_string()),
                doh: Some(true),
                block_quic: Some(true),
                ..Default::default()
            },
        )
        .expect("seed system config");

        let captured_cfg = RefCell::new(None::<FileConfig>);
        let sys_update = DnsConfigUpdateDto {
            dns_addr: "https://dns.nextdns.io/supersecret99".to_string(),
            doh_enabled: false,
            block_quic: false,
            tun_ipv6: true,
            ipv4_only: true,
            vpn_coexistence: VpnCoexistenceDto::Off,
            bypass_domains: vec!["bank.local".to_string()],
            include_domains: vec!["discord.com".to_string()],
        };
        let res_sys = save_dns_and_rules_with(
            sys_update,
            &sys_cfg_path,
            None,
            true,
            || ServiceState::Running,
            |cfg, system_scope, restart_if_running| {
                assert!(system_scope);
                assert!(restart_if_running);
                *captured_cfg.borrow_mut() = Some(cfg.clone());
                SidecarOutcome::Ok(String::new())
            },
        );
        assert!(res_sys.ok, "unexpected error: {}", res_sys.message);
        assert_eq!(res_sys.needs_restart, Some(false));
        assert!(res_sys.message.contains("https://dns.nextdns.io"));
        assert!(!res_sys.message.contains("supersecret99"));
        assert!(!res_sys.message.contains("Administrator/root"));

        let applied = captured_cfg
            .into_inner()
            .expect("apply_config_via_temp_file must be invoked");
        assert_eq!(applied.engine, Some(EngineMode::Tun));
        assert_eq!(
            applied.dns_addr.as_deref(),
            Some("https://dns.nextdns.io/supersecret99")
        );
        assert_eq!(applied.doh, Some(true));
        assert_eq!(applied.block_quic, Some(false));
        assert_eq!(applied.tun_ipv6, Some(true));
        assert_eq!(applied.ipv4_only, Some(true));
        assert_eq!(applied.vpn_coexistence, Some(VpnCoexistence::Off));
        assert_eq!(applied.bypass_domains, Some(vec!["bank.local".to_string()]));
        assert_eq!(
            applied.include_domains,
            Some(vec!["discord.com".to_string()])
        );

        // System service installed + non-DNS rule edit ONLY still delegates via temp-file sidecar.
        let mut rule_only_sys = base_dns_update();
        rule_only_sys.block_quic = false;
        let called_rule_only = Cell::new(false);
        let res_sys_rule = save_dns_and_rules_with(
            rule_only_sys,
            &sys_cfg_path,
            None,
            true,
            || ServiceState::Stopped,
            |cfg, system_scope, restart_if_running| {
                called_rule_only.set(true);
                assert!(system_scope);
                assert!(!restart_if_running);
                assert_eq!(cfg.block_quic, Some(false));
                SidecarOutcome::Cancelled
            },
        );
        assert!(called_rule_only.get());
        assert!(!res_sys_rule.ok);
        assert_eq!(res_sys_rule.message, "Elevation was cancelled.");
        assert_eq!(res_sys_rule.cancelled, Some(true));

        // System service installed + unchanged values skips elevation completely.
        let res_sys_noop = save_dns_and_rules_with(
            base_dns_update(),
            &sys_cfg_path,
            None,
            true,
            || ServiceState::Running,
            |_, _, _| unreachable!("unchanged system settings must not prompt for elevation"),
        );
        assert!(res_sys_noop.ok);
        assert_eq!(res_sys_noop.needs_restart, Some(false));

        // System service installed + partial save where service restart failed ->
        // `ok: true`, `needs_restart: Some(true)`, `cancelled: None`, URLs redacted.
        let mut restart_fail_update = base_dns_update();
        restart_fail_update.block_quic = false;
        let res_saved_needs_restart = save_dns_and_rules_with(
            restart_fail_update.clone(),
            &sys_cfg_path,
            None,
            true,
            || ServiceState::Running,
            |_, system_scope, restart_if_running| {
                assert!(system_scope);
                assert!(restart_if_running);
                SidecarOutcome::SavedNeedsRestart(
                    "restart failed for https://u:pw@dns.nextdns.io/secret99".to_string(),
                )
            },
        );
        assert!(res_saved_needs_restart.ok);
        assert_eq!(res_saved_needs_restart.needs_restart, Some(true));
        assert_eq!(res_saved_needs_restart.cancelled, None);
        assert!(res_saved_needs_restart
            .message
            .contains("https://dns.nextdns.io"));
        assert!(!res_saved_needs_restart.message.contains("secret99"));
        assert!(!res_saved_needs_restart.message.contains("pw"));

        let res_saved_needs_restart_empty = save_dns_and_rules_with(
            restart_fail_update,
            &sys_cfg_path,
            None,
            true,
            || ServiceState::Running,
            |_, _, _| SidecarOutcome::SavedNeedsRestart(String::new()),
        );
        assert!(res_saved_needs_restart_empty.ok);
        assert_eq!(res_saved_needs_restart_empty.needs_restart, Some(true));
        assert_eq!(res_saved_needs_restart_empty.cancelled, None);
        assert!(res_saved_needs_restart_empty.message.contains("Restart"));
    }

    #[test]
    fn install_and_uninstall_use_sidecar_handle_cancel_and_redact_errors() {
        let ok_install_tun = install_background_service_with(EngineMode::Tun, true, |args, elev| {
            assert_eq!(args, &["install", "--tun"]);
            assert!(elev);
            SidecarOutcome::Ok(String::new())
        });
        assert!(ok_install_tun.ok);
        assert!(ok_install_tun.message.contains("TUN"));
        assert_eq!(ok_install_tun.needs_restart, Some(false));

        let ok_install_proxy =
            install_background_service_with(EngineMode::Proxy, false, |args, elev| {
                assert_eq!(args, &["install", "--proxy"]);
                assert!(!elev);
                SidecarOutcome::Ok(String::new())
            });
        assert!(ok_install_proxy.ok);
        assert!(ok_install_proxy.message.contains("Proxy"));

        let cancel_install =
            install_background_service_with(EngineMode::Tun, true, |_, _| SidecarOutcome::Cancelled);
        assert!(!cancel_install.ok);
        assert_eq!(cancel_install.message, "Elevation was cancelled.");
        assert_eq!(cancel_install.cancelled, Some(true));

        let err_install = install_background_service_with(EngineMode::Tun, true, |_, _| {
            SidecarOutcome::Err("install error https://tok:sec@example.com/private".to_string())
        });
        assert!(!err_install.ok);
        assert!(!err_install.message.contains("private"));
        assert!(!err_install.message.contains("sec"));

        let ok_uninstall = uninstall_background_service_with(true, |args, elev| {
            assert_eq!(args, &["uninstall"]);
            assert!(!args.contains(&"--purge"));
            assert!(elev);
            SidecarOutcome::Ok(String::new())
        });
        assert!(ok_uninstall.ok);
        assert_eq!(ok_uninstall.needs_restart, Some(false));

        let cancel_uninstall =
            uninstall_background_service_with(true, |_, _| SidecarOutcome::Cancelled);
        assert!(!cancel_uninstall.ok);
        assert_eq!(cancel_uninstall.message, "Elevation was cancelled.");
        assert_eq!(cancel_uninstall.cancelled, Some(true));

        let err_uninstall = uninstall_background_service_with(true, |_, _| {
            SidecarOutcome::Err("uninstall error https://u:pw@host.test/secret".to_string())
        });
        assert!(!err_uninstall.ok);
        assert!(!err_uninstall.message.contains("secret"));
    }

    #[test]
    fn release_check_to_dto_maps_version_relations_and_validates_release_url() {
        let make = |relation, url: &str| ReleaseCheckResult {
            current_version: "0.6.0".to_string(),
            latest_version: "v0.7.0".to_string(),
            release_url: url.to_string(),
            release_notes: vec!["- Faster TUN path".to_string()],
            relation,
            asset_name: None,
            asset_url: None,
            sums_url: None,
            installed_service_path: None,
        };

        let newer = release_check_to_dto(make(
            VersionRelation::Newer,
            "https://github.com/Vuln-Inc/vdpi/releases/tag/v0.7.0",
        ));
        assert!(newer.has_update);
        assert_eq!(newer.current_version, "0.6.0");
        assert_eq!(newer.latest_version, "v0.7.0");
        assert_eq!(
            newer.release_url,
            "https://github.com/Vuln-Inc/vdpi/releases/tag/v0.7.0"
        );
        assert_eq!(newer.release_notes, vec!["- Faster TUN path"]);

        // Disallowed or malicious release_url is neutralized to canonical releases URL.
        let unsafe_dto = release_check_to_dto(make(
            VersionRelation::Newer,
            "https://evil.example/Vuln-Inc/vdpi/releases/tag/v0.7.0",
        ));
        assert_eq!(unsafe_dto.release_url, REPO_RELEASES_URL);

        let js_dto = release_check_to_dto(make(VersionRelation::Newer, "javascript:alert(1)"));
        assert_eq!(js_dto.release_url, REPO_RELEASES_URL);

        assert!(
            !release_check_to_dto(make(VersionRelation::Same, REPO_RELEASES_URL)).has_update
        );
        assert!(
            !release_check_to_dto(make(VersionRelation::Older, REPO_RELEASES_URL)).has_update
        );
        assert!(
            !release_check_to_dto(make(VersionRelation::Unknown, REPO_RELEASES_URL)).has_update
        );
    }

    #[test]
    fn open_external_url_enforces_strict_github_allowlist() {
        for valid in [
            "https://github.com/Vuln-Inc/vdpi",
            "https://github.com/Vuln-Inc/vdpi/",
            "https://github.com/Vuln-Inc/vdpi/releases",
            "https://github.com/Vuln-Inc/vdpi/releases/",
            "https://github.com/Vuln-Inc/vdpi/releases/latest",
            "https://github.com/Vuln-Inc/vdpi/releases/latest/",
            "https://github.com/Vuln-Inc/vdpi/releases/tag/v0.7.0",
            "https://github.com/Vuln-Inc/vdpi/releases/tag/v0.7.0/",
            "https://github.com/Vuln-Inc/vdpi/releases/tag/v0.7.0-rc.1+build2",
        ] {
            let opened = RefCell::new(None::<String>);
            let res = open_external_url_with(valid, |u| {
                *opened.borrow_mut() = Some(u.to_string());
                Ok(())
            });
            assert!(res.ok, "expected valid URL {valid} ok: {}", res.message);
            assert!(opened.borrow().is_some());
        }

        for rejected in [
            "",
            "   ",
            "http://github.com/Vuln-Inc/vdpi",
            "http://github.com/Vuln-Inc/vdpi/releases",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "ms-msdt:/id",
            "https://evil.com/Vuln-Inc/vdpi",
            "https://github.com.evil.com/Vuln-Inc/vdpi",
            "https://github.com@evil.com/Vuln-Inc/vdpi",
            "https://github.com/Vuln-Inc/vdpi-evil",
            "https://github.com/Vuln-Inc/vdpi/issues/1",
            "https://github.com/Vuln-Inc/vdpi/releases-evil",
            "https://github.com/Vuln-Inc/vdpi/releases/../issues",
            "https://github.com/Vuln-Inc/vdpi/releases//tag/v0.7.0",
            "https://github.com/Vuln-Inc/vdpi/releases/download/v0.7.0/vdpi-setup.exe",
            "https://github.com/Vuln-Inc/vdpi/releases/latest/download/vdpi.exe",
            "https://github.com/Vuln-Inc/vdpi/releases/tag",
            "https://github.com/Vuln-Inc/vdpi/releases/tag/",
            "https://github.com/Vuln-Inc/vdpi/releases/tag/.",
            "https://github.com/Vuln-Inc/vdpi/releases/tag/..",
            "https://github.com/Vuln-Inc/vdpi/releases/tag/v0.7.0/extra",
            "https://github.com/Vuln-Inc/vdpi/releases/edit/v0.7.0",
            "https://github.com/Vuln-Inc/vdpi/releases/new",
            "https://github.com/Vuln-Inc/vdpi/releases/tag/v0.7.0?x=1",
            "https://github.com/Vuln-Inc/vdpi/releases/tag/v0.7.0#frag",
            "https://github.com/Vuln-Inc/vdpi/releases/tag/%2e%2e",
            "https://github.com/Vuln-Inc/vdpi/releases/tag/v0.7.0\\evil",
            "https://github.com/Vuln-Inc/vdpi/releases/tag/v0.7.0\n",
            "https://github.com/Vuln-Inc/vdpi/releases/tag/v0.7.0 extra",
        ] {
            let res = open_external_url_with(rejected, |_| {
                unreachable!("disallowed URL must never be opened: {rejected}")
            });
            assert!(!res.ok, "URL must be rejected: {rejected}");
        }
    }

    #[test]
    fn windows_path_syntax_rejects_device_prefixes_unc_ads_and_traversal() {
        assert!(validate_windows_path_syntax(r"C:\Users\Arda\AppData\Local\vdpi").is_ok());
        assert!(validate_windows_path_syntax(r"C:\Program Files\vdpi\bin").is_ok());

        for bad in [
            "",
            r"\\.\C:\Program Files\vdpi",
            r"//./PhysicalDrive0",
            r"\??\C:\Program Files\vdpi",
            r"\\?\C:\Program Files\vdpi",
            r"\\?\UNC\attacker\share",
            r"\\attacker\share\vdpi",
            r"C:\Users\Arda\AppData\Local\vdpi:evil",
            r"C:\Users\Arda\AppData\Local\vdpi\logs::$DATA",
            r"C:\Users\Arda\AppData\Local\vdpi\..\Windows",
            r"C:\Users\Arda\AppData\Local\vdpi.",
            r"C:\Users\Arda\AppData\Local\vdpi ",
            r"C:relative\vdpi",
            r"relative\vdpi",
            "C:\\vdpi\nlogs",
        ] {
            assert!(
                validate_windows_path_syntax(bad).is_err(),
                "expected Windows path syntax rejection for {bad:?}"
            );
        }
    }

    #[test]
    fn open_directory_in_os_enforces_strict_allowlist_and_creates_user_logs() {
        let dir = TempDirGuard::new("open-dir");
        let cfg_dir = dir.path().join("config");
        let logs_dir = dir.path().join("logs");
        let app_dir = dir.path().join("app-bin");
        let other_dir = dir.path().join("other");
        let sub_dir = cfg_dir.join("nested");
        let file_path = dir.path().join("config-file");
        let missing_non_creatable = dir.path().join("missing-config");
        let missing_creatable_logs = dir.path().join("user-home").join(".vdpi").join("logs");

        fs::create_dir_all(&sub_dir).expect("create cfg & sub dir");
        fs::create_dir_all(&logs_dir).expect("create logs dir");
        fs::create_dir_all(&app_dir).expect("create app dir");
        fs::create_dir_all(&other_dir).expect("create other dir");
        fs::write(&file_path, b"not a dir").expect("create regular file");

        let allowed = vec![
            AllowedDirectory {
                path: cfg_dir.clone(),
                create_if_missing: false,
            },
            AllowedDirectory {
                path: logs_dir.clone(),
                create_if_missing: true,
            },
            AllowedDirectory {
                path: app_dir.clone(),
                create_if_missing: false,
            },
            AllowedDirectory {
                path: file_path.clone(),
                create_if_missing: false,
            },
            AllowedDirectory {
                path: missing_non_creatable.clone(),
                create_if_missing: false,
            },
            AllowedDirectory {
                path: missing_creatable_logs.clone(),
                create_if_missing: true,
            },
        ];

        // Allowlisted config dir succeeds and omits raw path from toast.
        let opened = RefCell::new(None::<PathBuf>);
        let res = open_directory_in_os_with(&cfg_dir, &allowed, |p| {
            *opened.borrow_mut() = Some(p.to_path_buf());
            Ok(())
        });
        assert!(res.ok, "expected allowlisted dir ok: {}", res.message);
        assert_eq!(opened.borrow().as_deref(), Some(cfg_dir.as_path()));
        assert!(!res.message.contains(&cfg_dir.display().to_string()));

        // Allowlisted logs and app/install dirs succeed.
        assert!(open_directory_in_os_with(&logs_dir, &allowed, |_| Ok(())).ok);
        assert!(open_directory_in_os_with(&app_dir, &allowed, |_| Ok(())).ok);

        // Missing user logs dir with `create_if_missing = true` is created and opened.
        assert!(!missing_creatable_logs.exists());
        let res_created = open_directory_in_os_with(&missing_creatable_logs, &allowed, |p| {
            assert_eq!(p, missing_creatable_logs.as_path());
            Ok(())
        });
        assert!(
            res_created.ok,
            "expected user logs auto-create ok: {}",
            res_created.message
        );
        assert!(missing_creatable_logs.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::symlink_metadata(&missing_creatable_logs)
                .expect("stat created user logs dir")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "created user logs dir must be owner-only 0700");
        }

        // Non-allowlisted sibling, parent, and child directories are rejected.
        for rejected in [&other_dir, dir.path(), &sub_dir] {
            let res = open_directory_in_os_with(rejected, &allowed, |_| {
                unreachable!("non-allowlisted dir must never be opened")
            });
            assert!(!res.ok);
            assert!(res.message.contains("outside"));
        }

        // Parent traversal is explicitly rejected even if it would resolve to an allowed dir.
        let traversal = cfg_dir.join("..").join("logs");
        let res_trav = open_directory_in_os_with(&traversal, &allowed, |_| {
            unreachable!("traversal must never be opened")
        });
        assert!(!res_trav.ok);
        assert!(res_trav.message.contains("traversal"));

        // Regular file is rejected even if listed.
        let res_file = open_directory_in_os_with(&file_path, &allowed, |_| {
            unreachable!("file must not be opened as dir")
        });
        assert!(!res_file.ok);
        assert!(res_file.message.contains("not a directory"));

        // Missing non-creatable allowlisted directory returns clean error without invoking launcher.
        let res_missing = open_directory_in_os_with(&missing_non_creatable, &allowed, |_| {
            unreachable!("missing dir must not be opened")
        });
        assert!(!res_missing.ok);
        assert!(res_missing.message.contains("does not exist"));

        // Empty path and control characters are rejected.
        let res_empty = open_directory_in_os_with(Path::new(""), &allowed, |_| unreachable!());
        assert!(!res_empty.ok);
        let res_ctrl =
            open_directory_in_os_with(Path::new("/tmp/vdpi\nbad"), &allowed, |_| unreachable!());
        assert!(!res_ctrl.ok);
    }

    #[cfg(unix)]
    #[test]
    fn open_directory_in_os_rejects_leaf_and_intermediate_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = TempDirGuard::new("open-dir-symlink");
        let real_target = dir.path().join("real-target");
        fs::create_dir_all(&real_target).expect("create real target");

        let leaf_link = dir.path().join("leaf-link");
        symlink(&real_target, &leaf_link).expect("create leaf symlink");

        let parent_link = dir.path().join("parent-link");
        symlink(&real_target, &parent_link).expect("create parent symlink");
        let nested_under_link = parent_link.join("logs");

        let allowed = vec![
            AllowedDirectory {
                path: leaf_link.clone(),
                create_if_missing: false,
            },
            AllowedDirectory {
                path: nested_under_link.clone(),
                create_if_missing: true,
            },
        ];

        // Leaf symlink rejected even if listed in allowlist.
        let res_leaf = open_directory_in_os_with(&leaf_link, &allowed, |_| {
            unreachable!("symlink must never be opened")
        });
        assert!(!res_leaf.ok);
        assert!(res_leaf.message.contains("symbolic link"));

        // Intermediate symlink ancestor rejected before `create_if_missing` creates anything.
        let res_parent = open_directory_in_os_with(&nested_under_link, &allowed, |_| {
            unreachable!("path under symlink must never be opened")
        });
        assert!(!res_parent.ok);
        assert!(res_parent.message.contains("symbolic link"));
        assert!(!real_target.join("logs").exists());
    }

    #[test]
    fn sanitize_linux_launcher_env_strips_loader_and_gtk_injection_vars() {
        let mut cmd = std::process::Command::new("/usr/bin/xdg-open");
        sanitize_linux_launcher_env(&mut cmd);

        let removed: HashSet<String> = cmd
            .get_envs()
            .filter(|(_, v)| v.is_none())
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();

        for expected in [
            "LD_LIBRARY_PATH",
            "LD_PRELOAD",
            "LD_AUDIT",
            "APPDIR",
            "APPIMAGE",
            "GTK_PATH",
            "GIO_EXTRA_MODULES",
            "GIO_MODULE_DIR",
            "GDK_PIXBUF_MODULE_FILE",
            "GDK_PIXBUF_MODULEDIR",
            "GSETTINGS_SCHEMA_DIR",
            "GTK_IM_MODULE_FILE",
        ] {
            assert!(
                removed.contains(expected),
                "expected env var {expected} to be removed from Linux launcher"
            );
        }
    }

    #[test]
    fn allowed_os_system_symlink_paths_support_linux_ostree_and_macos_root_only() {
        for path in ["/home", "/usr/local", "/var", "/tmp", "/etc"] {
            assert!(
                is_allowed_os_system_symlink_path(Path::new(path), 0, true),
                "Linux must allow root-owned OS/ostree link {path}"
            );
            assert!(
                !is_allowed_os_system_symlink_path(Path::new(path), 1000, true),
                "Linux must reject non-root link {path}"
            );
        }

        for path in ["/var", "/tmp", "/etc"] {
            assert!(
                is_allowed_os_system_symlink_path(Path::new(path), 0, false),
                "macOS must allow root-owned OS link {path}"
            );
            assert!(
                !is_allowed_os_system_symlink_path(Path::new(path), 501, false),
                "macOS must reject non-root link {path}"
            );
        }
        assert!(!is_allowed_os_system_symlink_path(
            Path::new("/home"),
            0,
            false
        ));
        assert!(!is_allowed_os_system_symlink_path(
            Path::new("/usr/local"),
            0,
            false
        ));

        for rejected in [
            "/opt",
            "/usr/local/bin",
            "/home/alice",
            "/var/log",
            "/tmp/vdpi",
            "/etc/vdpi",
        ] {
            assert!(
                !is_allowed_os_system_symlink_path(Path::new(rejected), 0, true),
                "Linux must reject non-allowlisted link {rejected}"
            );
            assert!(
                !is_allowed_os_system_symlink_path(Path::new(rejected), 0, false),
                "macOS must reject non-allowlisted link {rejected}"
            );
        }
    }

    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    #[test]
    fn wait_briefly_or_detach_launcher_surfaces_early_failures_and_allows_ok() {
        assert_eq!(
            XDG_OPEN_EARLY_EXIT_WAIT,
            std::time::Duration::from_millis(150)
        );

        let spawn_exit = |code: i32| -> Child {
            #[cfg(target_os = "windows")]
            {
                Command::new("cmd")
                    .args(["/C", "exit", &code.to_string()])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn cmd exit")
            }
            #[cfg(not(target_os = "windows"))]
            {
                Command::new("/bin/sh")
                    .args(["-c", &format!("exit {code}")])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn sh exit")
            }
        };

        let ok_res = wait_briefly_or_detach_launcher_with_timeout(
            spawn_exit(0),
            "Failed to launch default web browser",
            std::time::Duration::from_millis(1000),
        );
        assert!(ok_res.is_ok(), "exit 0 must succeed: {ok_res:?}");

        let err_res = wait_briefly_or_detach_launcher_with_timeout(
            spawn_exit(1),
            "Failed to launch default web browser",
            std::time::Duration::from_millis(1000),
        );
        let err_msg = err_res.expect_err("non-zero early exit must surface as Err");
        assert!(err_msg.contains("Failed to launch default web browser"));
        assert!(err_msg.contains("exit code 1"));

        #[cfg(unix)]
        {
            let long_child = Command::new("/bin/sh")
                .args(["-c", "sleep 0.3"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn sleeping child");
            let detached = wait_briefly_or_detach_launcher_with_timeout(
                long_child,
                "Failed to open folder in file manager",
                std::time::Duration::from_millis(40),
            );
            assert!(
                detached.is_ok(),
                "long-running launcher should detach cleanly: {detached:?}"
            );
        }
    }

    #[test]
    fn macos_var_log_alias_and_platform_log_allowlists_are_configured() {
        assert_eq!(
            map_macos_var_log_alias(Path::new("/var/log")),
            PathBuf::from("/private/var/log")
        );
        assert_eq!(
            map_macos_var_log_alias(Path::new("/var/log/")),
            PathBuf::from("/private/var/log")
        );
        assert_eq!(
            map_macos_var_log_alias(Path::new("/var/./log")),
            PathBuf::from("/private/var/log")
        );
        assert_eq!(
            map_macos_var_log_alias(Path::new("/private/var/log")),
            PathBuf::from("/private/var/log")
        );
        assert_eq!(
            map_macos_var_log_alias(Path::new("/var/log/vdpi")),
            PathBuf::from("/var/log/vdpi")
        );
        assert_eq!(
            map_macos_var_log_alias(Path::new("/var/log/../etc")),
            PathBuf::from("/var/log/../etc")
        );
        assert_eq!(
            map_macos_var_log_alias(Path::new("/var/log\n")),
            PathBuf::from("/var/log\n")
        );

        #[cfg(target_os = "macos")]
        {
            let allowed = allowed_vdpi_directories();
            let entry = allowed
                .iter()
                .find(|d| d.path == Path::new("/private/var/log"))
                .expect("macOS must allowlist /private/var/log");
            assert!(!entry.create_if_missing);
        }

        #[cfg(target_os = "linux")]
        {
            let allowed = allowed_vdpi_directories();
            for expected in ["/var/log/vdpi", "/var/log"] {
                let entry = allowed
                    .iter()
                    .find(|d| d.path == Path::new(expected))
                    .unwrap_or_else(|| panic!("Linux must allowlist {expected}"));
                assert!(!entry.create_if_missing);
            }
        }
    }

    #[test]
    fn uninstall_needs_elevation_detects_regular_files_and_broken_symlinks() {
        let dir = TempDirGuard::new("uninstall-elev");
        let missing = dir.path().join("does-not-exist");
        let regular = dir.path().join("vdpi");
        fs::write(&regular, b"bin").expect("create regular file");

        assert!(!uninstall_needs_elevation_for_paths(&[missing.as_path()]));
        assert!(uninstall_needs_elevation_for_paths(&[
            missing.as_path(),
            regular.as_path()
        ]));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let broken_link = dir.path().join("broken-vdpi-link");
            symlink(dir.path().join("missing-target"), &broken_link)
                .expect("create broken symlink");
            assert!(!broken_link.exists());
            assert!(uninstall_needs_elevation_for_paths(&[
                broken_link.as_path()
            ]));
        }
    }
}
