//! Cross-platform network reset orchestrator.
//!
//! Restores OS proxy settings, proxy environment variables, WinHTTP (Windows),
//! TUN adapters/routes, DNS overrides, and DNS resolver caches back to clean
//! operating system defaults while stopping any running `vdpi` daemons.

use crate::i18n::Lang;
use serde::{Deserialize, Serialize};

/// Scope of a network reset operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResetScope {
    /// Reset both system-wide (privileged) and per-user network subsystems.
    Full,
    /// Reset only per-user subsystems that do not require administrator/root privileges.
    UserOnly,
}

/// Outcome status for an individual network subsystem reset step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubsystemStatus {
    /// Non-default state was found and restored to OS defaults.
    Reset,
    /// Subsystem was already at clean OS defaults.
    AlreadyDefault,
    /// Subsystem required administrator/root privileges and was skipped.
    SkippedPrivileges,
    /// One or more errors occurred while resetting this subsystem.
    Failed,
}

/// Structured status entry for a single subsystem touched by [`reset_network_defaults`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubsystemResetItem {
    /// Canonical identifier: `"service"`, `"proxy"`, `"env_proxy"`, `"winhttp"`,
    /// `"tun_routes"`, `"dns_override"`, or `"dns_cache"`.
    pub id: String,
    pub status: SubsystemStatus,
    pub detail: Option<String>,
}

/// Aggregated report returned by [`reset_network_defaults`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkResetReport {
    pub scope: ResetScope,
    pub elevated: bool,
    pub items: Vec<SubsystemResetItem>,
}

impl NetworkResetReport {
    /// Returns `true` if any subsystem reported [`SubsystemStatus::Failed`].
    pub fn has_failures(&self) -> bool {
        self.items
            .iter()
            .any(|item| item.status == SubsystemStatus::Failed)
    }

    /// Returns `true` if any subsystem was skipped due to insufficient privileges.
    pub fn has_skipped_privileged(&self) -> bool {
        self.items
            .iter()
            .any(|item| item.status == SubsystemStatus::SkippedPrivileges)
    }

    /// Merges a follow-up interactive user-session pass (e.g. unelevated parent after
    /// an elevated child) into this report.
    ///
    /// Rules:
    /// - If an item was `AlreadyDefault` or `SkippedPrivileges` in this report and `Reset`
    ///   in `user_pass`, it upgrades to `Reset`.
    /// - Never overwrites `Reset` with `AlreadyDefault` or `SkippedPrivileges`.
    /// - Never downgrades `Failed`; merges failure details if both passes failed.
    /// - When this report already ran elevated (`self.elevated`), an unelevated
    ///   `SkippedPrivileges` in `user_pass` never downgrades an `AlreadyDefault` item.
    pub fn merge_user_pass(&mut self, user_pass: NetworkResetReport) {
        let self_elevated = self.elevated;
        for incoming in user_pass.items {
            if let Some(existing) = self.items.iter_mut().find(|item| item.id == incoming.id) {
                merge_subsystem_item(existing, incoming, self_elevated);
            } else {
                self.items.push(incoming);
            }
        }
    }

    /// Renders a clean itemized CLI summary with `[ok]` / `[skip]` / `[fail]` tags
    /// in English or Turkish (never using em dashes).
    pub fn format_cli_summary(&self, lang: Lang) -> String {
        let mut out = String::new();
        let header = match (lang, self.scope) {
            (Lang::En, ResetScope::Full) => "Network reset summary (scope: full):",
            (Lang::En, ResetScope::UserOnly) => "Network reset summary (scope: user-only):",
            (Lang::Tr, ResetScope::Full) => "Ağ sıfırlama özeti (kapsam: tam):",
            (Lang::Tr, ResetScope::UserOnly) => {
                "Ağ sıfırlama özeti (kapsam: yalnızca kullanıcı):"
            }
        };
        out.push_str(header);

        for item in &self.items {
            let tag = match item.status {
                SubsystemStatus::Reset | SubsystemStatus::AlreadyDefault => "[ok]",
                SubsystemStatus::SkippedPrivileges => "[skip]",
                SubsystemStatus::Failed => "[fail]",
            };
            let label = subsystem_label(&item.id, lang);
            let status_text = subsystem_status_text(item.status, lang);
            out.push_str(&format!("\n  {tag} {label}: {status_text}"));
            if let Some(detail) = item
                .detail
                .as_deref()
                .map(str::trim)
                .filter(|d| !d.is_empty())
            {
                let clean = sanitize_no_em_dash(detail);
                out.push_str(&format!(" ({clean})"));
            }
        }

        if self.has_skipped_privileged() {
            let note = match lang {
                Lang::En => {
                    "\nNote: re-run with administrator privileges to reset skipped system subsystems."
                }
                Lang::Tr => {
                    "\nNot: atlanan sistem alt bileşenlerini sıfırlamak için yönetici yetkisiyle yeniden çalıştırın."
                }
            };
            out.push_str(note);
        }

        out
    }

    /// Renders a concise single-line summary suitable for GUI toasts and TUI notice
    /// banners in English or Turkish (never using em dashes).
    pub fn format_short_summary(&self, lang: Lang) -> String {
        let mut reset_count = 0usize;
        let mut skipped_count = 0usize;
        let mut failed_count = 0usize;

        for item in &self.items {
            match item.status {
                SubsystemStatus::Reset => reset_count += 1,
                SubsystemStatus::SkippedPrivileges => skipped_count += 1,
                SubsystemStatus::Failed => failed_count += 1,
                SubsystemStatus::AlreadyDefault => {}
            }
        }

        if failed_count > 0 {
            return match lang {
                Lang::En if skipped_count > 0 => format!(
                    "Network reset finished with {failed_count} error(s) ({reset_count} reset, {skipped_count} skipped)."
                ),
                Lang::En => format!(
                    "Network reset finished with {failed_count} error(s) ({reset_count} reset)."
                ),
                Lang::Tr if skipped_count > 0 => format!(
                    "Ağ sıfırlama {failed_count} hata ile tamamlandı ({reset_count} sıfırlandı, {skipped_count} atlandı)."
                ),
                Lang::Tr => format!(
                    "Ağ sıfırlama {failed_count} hata ile tamamlandı ({reset_count} sıfırlandı)."
                ),
            };
        }

        if skipped_count > 0 {
            return match lang {
                Lang::En => format!(
                    "User network settings reset ({reset_count} reset, {skipped_count} system item(s) skipped - admin required)."
                ),
                Lang::Tr => format!(
                    "Kullanıcı ağ ayarları sıfırlandı ({reset_count} sıfırlandı, {skipped_count} sistem öğesi atlandı - yönetici gerekli)."
                ),
            };
        }

        if reset_count > 0 {
            return match lang {
                Lang::En => format!(
                    "Network settings restored to defaults ({reset_count} subsystem(s) reset)."
                ),
                Lang::Tr => format!(
                    "Ağ ayarları varsayılana döndürüldü ({reset_count} alt bileşen sıfırlandı)."
                ),
            };
        }

        match lang {
            Lang::En => "Network settings are already at OS defaults.".to_string(),
            Lang::Tr => "Ağ ayarları zaten işletim sistemi varsayılanında.".to_string(),
        }
    }
}

fn merge_subsystem_item(
    existing: &mut SubsystemResetItem,
    incoming: SubsystemResetItem,
    existing_elevated: bool,
) {
    match (existing.status, incoming.status) {
        (SubsystemStatus::Failed, SubsystemStatus::Failed) => {
            existing.detail = combine_details(existing.detail.take(), incoming.detail);
        }
        (SubsystemStatus::Failed, _) => {}
        (_, SubsystemStatus::Failed) => {
            existing.status = SubsystemStatus::Failed;
            existing.detail = incoming.detail.or_else(|| existing.detail.take());
        }
        (SubsystemStatus::Reset, _) => {
            if existing.detail.is_none() && incoming.status == SubsystemStatus::Reset {
                existing.detail = incoming.detail;
            }
        }
        (
            SubsystemStatus::AlreadyDefault | SubsystemStatus::SkippedPrivileges,
            SubsystemStatus::Reset,
        ) => {
            existing.status = SubsystemStatus::Reset;
            existing.detail = incoming.detail;
        }
        (SubsystemStatus::SkippedPrivileges, SubsystemStatus::AlreadyDefault) => {}
        (SubsystemStatus::AlreadyDefault, SubsystemStatus::SkippedPrivileges) => {
            if !existing_elevated {
                existing.status = SubsystemStatus::SkippedPrivileges;
                existing.detail = incoming.detail.or_else(|| existing.detail.take());
            }
        }
        (SubsystemStatus::AlreadyDefault, SubsystemStatus::AlreadyDefault)
        | (SubsystemStatus::SkippedPrivileges, SubsystemStatus::SkippedPrivileges) => {
            if existing.detail.is_none() {
                existing.detail = incoming.detail;
            }
        }
    }
}

fn combine_details(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(left), Some(right)) => {
            let l = left.trim();
            let r = right.trim();
            if l.is_empty() {
                (!r.is_empty()).then(|| r.to_string())
            } else if r.is_empty() || l == r {
                Some(l.to_string())
            } else {
                Some(format!("{l}; {r}"))
            }
        }
        (Some(left), None) => {
            let l = left.trim();
            (!l.is_empty()).then(|| l.to_string())
        }
        (None, Some(right)) => {
            let r = right.trim();
            (!r.is_empty()).then(|| r.to_string())
        }
        (None, None) => None,
    }
}

fn sanitize_no_em_dash(text: &str) -> String {
    text.replace('\u{2014}', "-")
}

fn subsystem_label(id: &str, lang: Lang) -> &str {
    match (id, lang) {
        ("service", Lang::En) => "Background service / daemons",
        ("service", Lang::Tr) => "Arka plan servisi / süreçler",
        ("proxy", Lang::En) => "System proxy",
        ("proxy", Lang::Tr) => "Sistem proxy'si",
        ("env_proxy", Lang::En) => "Proxy environment variables",
        ("env_proxy", Lang::Tr) => "Proxy ortam değişkenleri",
        ("winhttp", Lang::En) => "WinHTTP proxy",
        ("winhttp", Lang::Tr) => "WinHTTP proxy",
        ("tun_routes", Lang::En) => "TUN adapter & routes",
        ("tun_routes", Lang::Tr) => "TUN bağdaştırıcısı ve rotalar",
        ("dns_override", Lang::En) => "DNS override",
        ("dns_override", Lang::Tr) => "DNS geçersiz kılma",
        ("dns_cache", Lang::En) => "DNS resolver cache",
        ("dns_cache", Lang::Tr) => "DNS çözümleyici önbelleği",
        (other, _) => other,
    }
}

fn subsystem_status_text(status: SubsystemStatus, lang: Lang) -> &'static str {
    match (status, lang) {
        (SubsystemStatus::Reset, Lang::En) => "reset to defaults",
        (SubsystemStatus::AlreadyDefault, Lang::En) => "already default",
        (SubsystemStatus::SkippedPrivileges, Lang::En) => "skipped (admin privileges required)",
        (SubsystemStatus::Failed, Lang::En) => "failed",
        (SubsystemStatus::Reset, Lang::Tr) => "varsayılana sıfırlandı",
        (SubsystemStatus::AlreadyDefault, Lang::Tr) => "zaten varsayılan",
        (SubsystemStatus::SkippedPrivileges, Lang::Tr) => "atlandı (yönetici yetkisi gerekli)",
        (SubsystemStatus::Failed, Lang::Tr) => "başarısız",
    }
}

fn process_is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        crate::platform::windows_service::is_elevated()
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        crate::service::is_unix_root()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

fn make_item(id: &str, status: SubsystemStatus, detail: Option<String>) -> SubsystemResetItem {
    SubsystemResetItem {
        id: id.to_string(),
        status,
        detail: detail
            .map(|d| sanitize_no_em_dash(d.trim()))
            .filter(|d| !d.is_empty()),
    }
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
fn join_errors(errors: &[String]) -> Option<String> {
    if errors.is_empty() {
        None
    } else {
        Some(errors.join("; "))
    }
}

/// Orchestrates a complete (or user-only) OS network reset back to factory defaults:
///
/// 1. Stops running `vdpi` background services and foreground daemons, then clears stale
///    runtime `state.json` files.
/// 2. Resets OS proxy / PAC / environment variables (and WinHTTP on Windows).
/// 3. Cleans up TUN adapters, routes, and DNS overrides.
/// 4. Flushes the OS DNS resolver cache unconditionally.
pub fn reset_network_defaults(scope: ResetScope) -> NetworkResetReport {
    let effective_elevated = matches!(scope, ResetScope::Full) && process_is_elevated();
    let mut items = Vec::with_capacity(7);

    // 1. Stop running daemons / services and clear stale runtime state files.
    let (stopped_any, service_skipped_priv, service_errors) =
        crate::service::stop_all_vdpi_daemons_for_reset(effective_elevated);
    crate::service::clear_all_stale_runtime_states();

    let service_item = if !service_errors.is_empty() {
        make_item(
            "service",
            SubsystemStatus::Failed,
            Some(service_errors.join("; ")),
        )
    } else if service_skipped_priv {
        let detail = if stopped_any {
            "stopped user daemon; system service requires admin privileges"
        } else {
            "system service requires admin privileges"
        };
        make_item(
            "service",
            SubsystemStatus::SkippedPrivileges,
            Some(detail.to_string()),
        )
    } else if stopped_any {
        make_item("service", SubsystemStatus::Reset, None)
    } else {
        make_item("service", SubsystemStatus::AlreadyDefault, None)
    };
    items.push(service_item);

    // 2. OS proxy / PAC / env / WinHTTP reset.
    reset_proxy_subsystems(effective_elevated, &mut items);

    // 3. OS TUN / routes / DNS override reset.
    reset_tun_and_dns_subsystems(scope, effective_elevated, &mut items);

    // 4. Unconditional DNS resolver cache flush.
    items.push(flush_os_dns_cache(effective_elevated));

    NetworkResetReport {
        scope,
        elevated: effective_elevated,
        items,
    }
}

fn reset_proxy_subsystems(effective_elevated: bool, items: &mut Vec<SubsystemResetItem>) {
    #[cfg(target_os = "windows")]
    {
        let outcome =
            crate::platform::windows::reset_windows_proxies_to_defaults(effective_elevated);
        let mut wininet_errors = Vec::new();
        let mut env_errors = Vec::new();
        let mut winhttp_errors = Vec::new();

        for err in outcome.errors {
            let lower = err.to_ascii_lowercase();
            if lower.contains("winhttp") {
                winhttp_errors.push(err);
            } else if lower.contains("environment") {
                env_errors.push(err);
            } else {
                wininet_errors.push(err);
            }
        }

        let proxy_status = if !wininet_errors.is_empty() {
            SubsystemStatus::Failed
        } else if outcome.wininet_changed {
            SubsystemStatus::Reset
        } else {
            SubsystemStatus::AlreadyDefault
        };
        items.push(make_item("proxy", proxy_status, join_errors(&wininet_errors)));

        let env_status = if !env_errors.is_empty() {
            SubsystemStatus::Failed
        } else if outcome.env_changed {
            SubsystemStatus::Reset
        } else {
            SubsystemStatus::AlreadyDefault
        };
        items.push(make_item("env_proxy", env_status, join_errors(&env_errors)));

        let (winhttp_status, winhttp_detail) = if !winhttp_errors.is_empty() {
            (SubsystemStatus::Failed, join_errors(&winhttp_errors))
        } else if outcome.winhttp_skipped_privileges {
            (
                SubsystemStatus::SkippedPrivileges,
                Some("WinHTTP reset requires admin privileges".to_string()),
            )
        } else if outcome.winhttp_changed {
            (SubsystemStatus::Reset, None)
        } else {
            (SubsystemStatus::AlreadyDefault, None)
        };
        items.push(make_item("winhttp", winhttp_status, winhttp_detail));
    }

    #[cfg(target_os = "macos")]
    {
        let _ = effective_elevated;
        let outcome = crate::platform::macos::reset_macos_proxies_to_defaults();
        let mut proxy_errors = Vec::new();
        let mut env_errors = Vec::new();

        for err in outcome.errors {
            let lower = err.to_ascii_lowercase();
            if lower.contains("launchctl") || lower.contains("env") {
                env_errors.push(err);
            } else {
                proxy_errors.push(err);
            }
        }

        let (proxy_status, proxy_detail) = if !proxy_errors.is_empty() {
            (SubsystemStatus::Failed, join_errors(&proxy_errors))
        } else if outcome.skipped_privileges {
            (
                SubsystemStatus::SkippedPrivileges,
                Some("networksetup requires admin privileges".to_string()),
            )
        } else if outcome.proxy_changed {
            (SubsystemStatus::Reset, None)
        } else {
            (SubsystemStatus::AlreadyDefault, None)
        };
        items.push(make_item("proxy", proxy_status, proxy_detail));

        let env_status = if !env_errors.is_empty() {
            SubsystemStatus::Failed
        } else if outcome.env_changed {
            SubsystemStatus::Reset
        } else {
            SubsystemStatus::AlreadyDefault
        };
        items.push(make_item("env_proxy", env_status, join_errors(&env_errors)));
    }

    #[cfg(target_os = "linux")]
    {
        let _ = effective_elevated;
        let outcome = crate::platform::linux::reset_linux_proxies_to_defaults();
        let mut proxy_errors = Vec::new();
        let mut env_errors = Vec::new();

        for err in outcome.errors {
            let lower = err.to_ascii_lowercase();
            if lower.contains("systemctl") || lower.contains("environment") || lower.contains("env") {
                env_errors.push(err);
            } else {
                proxy_errors.push(err);
            }
        }

        let (proxy_status, proxy_detail) = if !proxy_errors.is_empty() {
            (SubsystemStatus::Failed, join_errors(&proxy_errors))
        } else if outcome.skipped_privileges {
            (
                SubsystemStatus::SkippedPrivileges,
                Some("system proxy reset requires elevated privileges".to_string()),
            )
        } else if outcome.proxy_changed {
            (SubsystemStatus::Reset, None)
        } else {
            (SubsystemStatus::AlreadyDefault, None)
        };
        items.push(make_item("proxy", proxy_status, proxy_detail));

        let env_status = if !env_errors.is_empty() {
            SubsystemStatus::Failed
        } else if outcome.env_changed {
            SubsystemStatus::Reset
        } else {
            SubsystemStatus::AlreadyDefault
        };
        items.push(make_item("env_proxy", env_status, join_errors(&env_errors)));
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = effective_elevated;
        items.push(make_item("proxy", SubsystemStatus::AlreadyDefault, None));
        items.push(make_item("env_proxy", SubsystemStatus::AlreadyDefault, None));
    }
}

fn reset_tun_and_dns_subsystems(
    scope: ResetScope,
    effective_elevated: bool,
    items: &mut Vec<SubsystemResetItem>,
) {
    #[cfg(target_os = "windows")]
    {
        let _ = scope;
        if !effective_elevated {
            items.push(make_item(
                "tun_routes",
                SubsystemStatus::SkippedPrivileges,
                Some("Wintun adapter and route reset requires admin privileges".to_string()),
            ));
            items.push(make_item(
                "dns_override",
                SubsystemStatus::SkippedPrivileges,
                Some("system interface DNS reset requires admin privileges".to_string()),
            ));
            return;
        }

        let (tun_changed, dns_changed, all_errors) =
            crate::platform::windows_tun::reset_windows_tun_and_dns_defaults();
        let mut tun_errors = Vec::new();
        let mut dns_errors = Vec::new();
        for err in all_errors {
            let lower = err.to_ascii_lowercase();
            if lower.contains("nameserver") || lower.contains("tcpip") || lower.contains("dns") {
                dns_errors.push(err);
            } else {
                tun_errors.push(err);
            }
        }

        let tun_status = if !tun_errors.is_empty() {
            SubsystemStatus::Failed
        } else if tun_changed {
            SubsystemStatus::Reset
        } else {
            SubsystemStatus::AlreadyDefault
        };
        items.push(make_item("tun_routes", tun_status, join_errors(&tun_errors)));

        let dns_status = if !dns_errors.is_empty() {
            SubsystemStatus::Failed
        } else if dns_changed {
            SubsystemStatus::Reset
        } else {
            SubsystemStatus::AlreadyDefault
        };
        items.push(make_item(
            "dns_override",
            dns_status,
            join_errors(&dns_errors),
        ));
    }

    #[cfg(target_os = "macos")]
    {
        if !effective_elevated && scope == ResetScope::UserOnly {
            items.push(make_item(
                "tun_routes",
                SubsystemStatus::SkippedPrivileges,
                Some("macOS TUN route reset requires root privileges".to_string()),
            ));
            items.push(make_item(
                "dns_override",
                SubsystemStatus::SkippedPrivileges,
                Some("macOS DNS reset requires root privileges".to_string()),
            ));
            return;
        }

        let (tun_changed, dns_changed, skipped_priv, all_errors) =
            crate::platform::macos_tun::reset_macos_tun_and_dns_defaults();
        let mut tun_errors = Vec::new();
        let mut dns_errors = Vec::new();
        for err in all_errors {
            let lower = err.to_ascii_lowercase();
            if lower.contains("dns")
                || lower.contains("scutil")
                || lower.contains("networksetup")
            {
                dns_errors.push(err);
            } else {
                tun_errors.push(err);
            }
        }

        let (tun_status, tun_detail) = if !tun_errors.is_empty() {
            (SubsystemStatus::Failed, join_errors(&tun_errors))
        } else if skipped_priv {
            (
                SubsystemStatus::SkippedPrivileges,
                Some("macOS TUN route reset requires root privileges".to_string()),
            )
        } else if tun_changed {
            (SubsystemStatus::Reset, None)
        } else {
            (SubsystemStatus::AlreadyDefault, None)
        };
        items.push(make_item("tun_routes", tun_status, tun_detail));

        let (dns_status, dns_detail) = if !dns_errors.is_empty() {
            (SubsystemStatus::Failed, join_errors(&dns_errors))
        } else if skipped_priv {
            (
                SubsystemStatus::SkippedPrivileges,
                Some("macOS DNS reset requires root privileges".to_string()),
            )
        } else if dns_changed {
            (SubsystemStatus::Reset, None)
        } else {
            (SubsystemStatus::AlreadyDefault, None)
        };
        items.push(make_item("dns_override", dns_status, dns_detail));
    }

    #[cfg(target_os = "linux")]
    {
        if !effective_elevated && scope == ResetScope::UserOnly {
            items.push(make_item(
                "tun_routes",
                SubsystemStatus::SkippedPrivileges,
                Some("Linux TUN route reset requires root privileges".to_string()),
            ));
            items.push(make_item(
                "dns_override",
                SubsystemStatus::SkippedPrivileges,
                Some("Linux DNS reset requires root privileges".to_string()),
            ));
            return;
        }

        let (tun_changed, dns_changed, skipped_priv, all_errors) =
            crate::platform::linux_tun::reset_linux_tun_and_dns_defaults();
        let mut tun_errors = Vec::new();
        let mut dns_errors = Vec::new();
        for err in all_errors {
            let lower = err.to_ascii_lowercase();
            if lower.contains("dns")
                || lower.contains("resolv")
                || lower.contains("networkmanager")
            {
                dns_errors.push(err);
            } else {
                tun_errors.push(err);
            }
        }

        let (tun_status, tun_detail) = if !tun_errors.is_empty() {
            (SubsystemStatus::Failed, join_errors(&tun_errors))
        } else if skipped_priv {
            (
                SubsystemStatus::SkippedPrivileges,
                Some("Linux TUN route reset requires root privileges".to_string()),
            )
        } else if tun_changed {
            (SubsystemStatus::Reset, None)
        } else {
            (SubsystemStatus::AlreadyDefault, None)
        };
        items.push(make_item("tun_routes", tun_status, tun_detail));

        let (dns_status, dns_detail) = if !dns_errors.is_empty() {
            (SubsystemStatus::Failed, join_errors(&dns_errors))
        } else if skipped_priv {
            (
                SubsystemStatus::SkippedPrivileges,
                Some("Linux DNS reset requires root privileges".to_string()),
            )
        } else if dns_changed {
            (SubsystemStatus::Reset, None)
        } else {
            (SubsystemStatus::AlreadyDefault, None)
        };
        items.push(make_item("dns_override", dns_status, dns_detail));
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (scope, effective_elevated);
        items.push(make_item(
            "tun_routes",
            SubsystemStatus::AlreadyDefault,
            None,
        ));
        items.push(make_item(
            "dns_override",
            SubsystemStatus::AlreadyDefault,
            None,
        ));
    }
}

fn flush_os_dns_cache(effective_elevated: bool) -> SubsystemResetItem {
    #[cfg(target_os = "windows")]
    {
        let _ = effective_elevated;
        crate::platform::windows::flush_dns_resolver_cache();
        make_item("dns_cache", SubsystemStatus::Reset, None)
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::{Command, Stdio};

        let mut errors = Vec::new();
        match Command::new("/usr/bin/dscacheutil")
            .arg("-flushcache")
            .stdin(Stdio::null())
            .output()
        {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                errors.push(if stderr.is_empty() {
                    format!("dscacheutil -flushcache exited with {}", out.status)
                } else {
                    format!("dscacheutil -flushcache failed: {stderr}")
                });
            }
            Err(err) => {
                errors.push(format!("failed to execute /usr/bin/dscacheutil: {err}"));
            }
        }

        if effective_elevated {
            if let Ok(out) = Command::new("/usr/bin/killall")
                .args(["-HUP", "mDNSResponder"])
                .stdin(Stdio::null())
                .output()
            {
                if !out.status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    if !stderr.to_ascii_lowercase().contains("no matching processes") {
                        let trimmed = stderr.trim();
                        if !trimmed.is_empty() {
                            errors.push(format!("killall -HUP mDNSResponder failed: {trimmed}"));
                        }
                    }
                }
            }
        }

        if errors.is_empty() {
            make_item("dns_cache", SubsystemStatus::Reset, None)
        } else {
            make_item("dns_cache", SubsystemStatus::Failed, Some(errors.join("; ")))
        }
    }

    #[cfg(target_os = "linux")]
    {
        use std::path::Path;
        use std::process::{Command, Stdio};

        let _ = effective_elevated;
        let resolvectl_paths = [
            "/usr/bin/resolvectl",
            "/bin/resolvectl",
            "/usr/sbin/resolvectl",
            "/sbin/resolvectl",
        ];
        if let Some(bin) = resolvectl_paths.into_iter().find(|p| Path::new(p).is_file()) {
            return match Command::new(bin)
                .arg("flush-caches")
                .stdin(Stdio::null())
                .output()
            {
                Ok(out) if out.status.success() => {
                    make_item("dns_cache", SubsystemStatus::Reset, None)
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    let lower = stderr.to_ascii_lowercase();
                    if lower.contains("unit dbus-org.freedesktop.resolve1.service not found")
                        || lower.contains("not running")
                        || lower.contains("failed to flush caches: unit")
                        || lower.contains("could not activate remote peer")
                    {
                        make_item(
                            "dns_cache",
                            SubsystemStatus::AlreadyDefault,
                            Some("systemd-resolved inactive".to_string()),
                        )
                    } else {
                        make_item(
                            "dns_cache",
                            SubsystemStatus::Failed,
                            Some(if stderr.is_empty() {
                                format!("resolvectl flush-caches exited with {}", out.status)
                            } else {
                                stderr
                            }),
                        )
                    }
                }
                Err(err) => make_item(
                    "dns_cache",
                    SubsystemStatus::Failed,
                    Some(format!("failed to execute resolvectl: {err}")),
                ),
            };
        }

        make_item(
            "dns_cache",
            SubsystemStatus::AlreadyDefault,
            Some("resolvectl not installed".to_string()),
        )
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = effective_elevated;
        make_item("dns_cache", SubsystemStatus::AlreadyDefault, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_item(id: &str, status: SubsystemStatus, detail: Option<&str>) -> SubsystemResetItem {
        SubsystemResetItem {
            id: id.to_string(),
            status,
            detail: detail.map(str::to_string),
        }
    }

    #[test]
    fn report_failure_and_skip_predicates_work() {
        let clean = NetworkResetReport {
            scope: ResetScope::Full,
            elevated: true,
            items: vec![
                sample_item("service", SubsystemStatus::AlreadyDefault, None),
                sample_item("proxy", SubsystemStatus::Reset, None),
            ],
        };
        assert!(!clean.has_failures());
        assert!(!clean.has_skipped_privileged());

        let skipped = NetworkResetReport {
            scope: ResetScope::UserOnly,
            elevated: false,
            items: vec![
                sample_item("proxy", SubsystemStatus::Reset, None),
                sample_item("winhttp", SubsystemStatus::SkippedPrivileges, None),
            ],
        };
        assert!(!skipped.has_failures());
        assert!(skipped.has_skipped_privileged());

        let failed = NetworkResetReport {
            scope: ResetScope::Full,
            elevated: true,
            items: vec![
                sample_item("proxy", SubsystemStatus::Reset, None),
                sample_item("tun_routes", SubsystemStatus::Failed, Some("io error")),
            ],
        };
        assert!(failed.has_failures());
        assert!(!failed.has_skipped_privileged());
    }

    #[test]
    fn merge_user_pass_upgrades_cleanly_without_downgrading_resets() {
        let mut full = NetworkResetReport {
            scope: ResetScope::Full,
            elevated: true,
            items: vec![
                sample_item("service", SubsystemStatus::Reset, None),
                sample_item("proxy", SubsystemStatus::AlreadyDefault, None),
                sample_item(
                    "env_proxy",
                    SubsystemStatus::SkippedPrivileges,
                    Some("not in elevated session"),
                ),
                sample_item("winhttp", SubsystemStatus::AlreadyDefault, None),
                sample_item("tun_routes", SubsystemStatus::Failed, Some("route err")),
            ],
        };

        let user = NetworkResetReport {
            scope: ResetScope::UserOnly,
            elevated: false,
            items: vec![
                // Must NOT overwrite Reset with AlreadyDefault.
                sample_item("service", SubsystemStatus::AlreadyDefault, None),
                // Must upgrade AlreadyDefault -> Reset.
                sample_item("proxy", SubsystemStatus::Reset, None),
                // Must upgrade SkippedPrivileges -> Reset.
                sample_item("env_proxy", SubsystemStatus::Reset, None),
                // Elevated full pass already verified winhttp as AlreadyDefault;
                // unelevated user pass SkippedPrivileges must NOT downgrade it.
                sample_item("winhttp", SubsystemStatus::SkippedPrivileges, None),
                // Must NOT downgrade Failed to AlreadyDefault.
                sample_item("tun_routes", SubsystemStatus::AlreadyDefault, None),
                // New item appended.
                sample_item("dns_cache", SubsystemStatus::Reset, None),
            ],
        };

        full.merge_user_pass(user);

        let status_of = |id: &str| {
            full.items
                .iter()
                .find(|i| i.id == id)
                .map(|i| i.status)
                .expect("item present")
        };

        assert_eq!(status_of("service"), SubsystemStatus::Reset);
        assert_eq!(status_of("proxy"), SubsystemStatus::Reset);
        assert_eq!(status_of("env_proxy"), SubsystemStatus::Reset);
        assert_eq!(status_of("winhttp"), SubsystemStatus::AlreadyDefault);
        assert_eq!(status_of("tun_routes"), SubsystemStatus::Failed);
        assert_eq!(status_of("dns_cache"), SubsystemStatus::Reset);
        assert!(full.has_failures());
        assert!(!full.has_skipped_privileged());
    }

    #[test]
    fn merge_user_pass_combines_failure_details_and_preserves_unprivileged_skips() {
        let mut base = NetworkResetReport {
            scope: ResetScope::UserOnly,
            elevated: false,
            items: vec![
                sample_item("proxy", SubsystemStatus::Failed, Some("err-a")),
                sample_item("winhttp", SubsystemStatus::AlreadyDefault, None),
            ],
        };
        let user = NetworkResetReport {
            scope: ResetScope::UserOnly,
            elevated: false,
            items: vec![
                sample_item("proxy", SubsystemStatus::Failed, Some("err-b")),
                sample_item("winhttp", SubsystemStatus::SkippedPrivileges, None),
            ],
        };

        base.merge_user_pass(user);
        let proxy = base.items.iter().find(|i| i.id == "proxy").unwrap();
        assert_eq!(proxy.status, SubsystemStatus::Failed);
        assert_eq!(proxy.detail.as_deref(), Some("err-a; err-b"));
        assert!(base.has_skipped_privileged());
    }

    #[test]
    fn format_cli_summary_supports_en_and_tr_without_em_dashes() {
        let report = NetworkResetReport {
            scope: ResetScope::Full,
            elevated: false,
            items: vec![
                sample_item("service", SubsystemStatus::AlreadyDefault, None),
                sample_item("proxy", SubsystemStatus::Reset, None),
                sample_item("winhttp", SubsystemStatus::SkippedPrivileges, None),
                sample_item("tun_routes", SubsystemStatus::Failed, Some("denied")),
            ],
        };

        let en = report.format_cli_summary(Lang::En);
        assert!(en.contains("[ok]"));
        assert!(en.contains("[skip]"));
        assert!(en.contains("[fail]"));
        assert!(en.contains("System proxy: reset to defaults"));
        assert!(en.contains("TUN adapter & routes: failed (denied)"));
        assert!(en.contains("administrator privileges"));
        assert!(!en.contains('\u{2014}'));

        let tr = report.format_cli_summary(Lang::Tr);
        assert!(tr.contains("[ok]"));
        assert!(tr.contains("[skip]"));
        assert!(tr.contains("[fail]"));
        assert!(tr.contains("Sistem proxy'si: varsayılana sıfırlandı"));
        assert!(tr.contains("TUN bağdaştırıcısı ve rotalar: başarısız (denied)"));
        assert!(tr.contains("yönetici yetkisiyle"));
        assert!(!tr.contains('\u{2014}'));
    }

    #[test]
    fn format_short_summary_is_single_line_and_has_no_em_dashes_in_en_and_tr() {
        let cases = [
            NetworkResetReport {
                scope: ResetScope::Full,
                elevated: true,
                items: vec![sample_item("proxy", SubsystemStatus::AlreadyDefault, None)],
            },
            NetworkResetReport {
                scope: ResetScope::Full,
                elevated: true,
                items: vec![
                    sample_item("proxy", SubsystemStatus::Reset, None),
                    sample_item("dns_cache", SubsystemStatus::Reset, None),
                ],
            },
            NetworkResetReport {
                scope: ResetScope::UserOnly,
                elevated: false,
                items: vec![
                    sample_item("proxy", SubsystemStatus::Reset, None),
                    sample_item("tun_routes", SubsystemStatus::SkippedPrivileges, None),
                ],
            },
            NetworkResetReport {
                scope: ResetScope::Full,
                elevated: true,
                items: vec![
                    sample_item("proxy", SubsystemStatus::Reset, None),
                    sample_item("tun_routes", SubsystemStatus::Failed, Some("err")),
                ],
            },
        ];

        for report in &cases {
            for lang in [Lang::En, Lang::Tr] {
                let s = report.format_short_summary(lang);
                assert!(!s.is_empty());
                assert!(!s.contains('\n'), "short summary must be single-line: {s}");
                assert!(!s.contains('\u{2014}'), "em dash forbidden: {s}");
            }
        }

        let en_reset = cases[1].format_short_summary(Lang::En);
        assert!(en_reset.contains("2 subsystem(s) reset"));
        let tr_reset = cases[1].format_short_summary(Lang::Tr);
        assert!(tr_reset.contains("2 alt bileşen sıfırlandı"));

        let en_skip = cases[2].format_short_summary(Lang::En);
        assert!(en_skip.contains("1 system item(s) skipped - admin required"));
        let tr_skip = cases[2].format_short_summary(Lang::Tr);
        assert!(tr_skip.contains("1 sistem öğesi atlandı - yönetici gerekli"));
    }

    #[test]
    fn report_serializes_with_expected_camel_and_snake_case_contract() {
        let report = NetworkResetReport {
            scope: ResetScope::UserOnly,
            elevated: false,
            items: vec![sample_item(
                "env_proxy",
                SubsystemStatus::SkippedPrivileges,
                Some("test"),
            )],
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("\"scope\":\"user_only\""));
        assert!(json.contains("\"status\":\"skipped_privileges\""));
        assert!(json.contains("\"elevated\":false"));
        let roundtrip: NetworkResetReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(roundtrip.scope, ResetScope::UserOnly);
        assert_eq!(roundtrip.items.len(), 1);
        assert_eq!(roundtrip.items[0].status, SubsystemStatus::SkippedPrivileges);
    }
}
