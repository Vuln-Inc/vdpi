use crate::bypass::build_no_proxy_value;
use anyhow::Result;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info};

#[derive(Debug, Clone)]
pub struct LinuxProxySession {
    addr: IpAddr,
    http_port: u16,
    socks_port: Option<u16>,
    socks_configured: bool,
    gnome_configured: bool,
    kde_bin: Option<String>,
    systemd_env_configured: bool,
    no_proxy_csv: String,
    gsettings_ignore: String,
}

impl LinuxProxySession {
    pub fn activate(
        addr: IpAddr,
        http_port: u16,
        socks_port: Option<u16>,
        enable_socks_system_proxy: bool,
        enable_env_proxy: bool,
        extra_bypass: &[String],
    ) -> Result<Self> {
        let addr_str = addr.to_string();
        let port_str = http_port.to_string();
        let socks_configured = enable_socks_system_proxy && socks_port.is_some();
        let no_proxy_csv = build_no_proxy_value(extra_bypass);
        let gsettings_ignore = build_gsettings_ignore_hosts(extra_bypass);

        let gnome_configured = configure_gnome_proxy(
            &addr_str,
            &port_str,
            if socks_configured { socks_port } else { None },
            &gsettings_ignore,
        );

        let kde_bin = detect_kde_writer();
        if let Some(ref kbin) = kde_bin {
            configure_kde_proxy(
                kbin,
                &addr_str,
                http_port,
                if socks_configured { socks_port } else { None },
                &no_proxy_csv,
            );
        }

        let systemd_env_configured = if enable_env_proxy {
            let proxy_url = format!("http://{addr_str}:{http_port}");
            set_systemd_user_env(&proxy_url, &no_proxy_csv)
        } else {
            false
        };

        info!(
            gnome = gnome_configured,
            kde = kde_bin.is_some(),
            systemd_env = systemd_env_configured,
            "configured Linux desktop proxy integration"
        );

        Ok(Self {
            addr,
            http_port,
            socks_port,
            socks_configured,
            gnome_configured,
            kde_bin,
            systemd_env_configured,
            no_proxy_csv,
            gsettings_ignore,
        })
    }

    pub fn summary(&self) -> String {
        let mut backends = Vec::new();
        if self.gnome_configured {
            backends.push("GNOME gsettings");
        }
        if self.kde_bin.is_some() {
            backends.push("KDE kioslaverc");
        }
        if self.systemd_env_configured {
            backends.push("systemd user env");
        }
        if backends.is_empty() {
            "listening (export HTTP_PROXY / HTTPS_PROXY manually on headless Linux)".to_string()
        } else {
            format!("active ({})", backends.join(" + "))
        }
    }

    pub fn reconcile(&self) {
        if crate::platform::vpn::detect_active_vpn(None).is_full_tunnel() {
            debug!("full-tunnel VPN active; skipping Linux proxy reconciliation");
            return;
        }

        if self.gnome_configured {
            let mode_ok = Command::new("gsettings")
                .args(["get", "org.gnome.system.proxy", "mode"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("manual"))
                .unwrap_or(false);
            let port_ok = Command::new("gsettings")
                .args(["get", "org.gnome.system.proxy.http", "port"])
                .output()
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .trim()
                        .parse::<u16>()
                        .ok()
                        == Some(self.http_port)
                })
                .unwrap_or(false);

            if !mode_ok || !port_ok {
                let _ = configure_gnome_proxy(
                    &self.addr.to_string(),
                    &self.http_port.to_string(),
                    if self.socks_configured {
                        self.socks_port
                    } else {
                        None
                    },
                    &self.gsettings_ignore,
                );
            }
        }
        if let Some(ref kbin) = self.kde_bin {
            configure_kde_proxy(
                kbin,
                &self.addr.to_string(),
                self.http_port,
                if self.socks_configured {
                    self.socks_port
                } else {
                    None
                },
                &self.no_proxy_csv,
            );
        }
        if self.systemd_env_configured {
            let proxy_url = format!("http://{}:{}", self.addr, self.http_port);
            let _ = set_systemd_user_env(&proxy_url, &self.no_proxy_csv);
        }
    }

    pub fn deactivate(&self) {
        self.deactivate_scoped();
        debug!("restored Linux desktop proxy settings");
    }

    pub(super) fn deactivate_foreground(&self) {
        self.deactivate_scoped();
    }

    fn deactivate_scoped(&self) {
        if self.gnome_configured {
            let get = |schema, key| {
                Command::new("gsettings")
                    .args(["get", schema, key])
                    .output()
                    .ok()
                    .filter(|out| out.status.success())
                    .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
            };
            let addr_str = self.addr.to_string();
            let http_owned = [
                "org.gnome.system.proxy.http",
                "org.gnome.system.proxy.https",
            ]
            .into_iter()
            .any(|schema| {
                get(schema, "host").is_some_and(|host| host.trim_matches('\'') == addr_str)
                    && get(schema, "port")
                        .is_some_and(|port| port.parse::<u16>() == Ok(self.http_port))
            });
            let socks_owned = self.socks_configured
                && self.socks_port.is_some_and(|sp| {
                    get("org.gnome.system.proxy.socks", "host")
                        .is_some_and(|host| host.trim_matches('\'') == addr_str)
                        && get("org.gnome.system.proxy.socks", "port")
                            .is_some_and(|port| port.parse::<u16>() == Ok(sp))
                });
            if (http_owned || socks_owned)
                && get("org.gnome.system.proxy", "mode").as_deref() == Some("'manual'")
            {
                let _ = Command::new("gsettings")
                    .args(["set", "org.gnome.system.proxy", "mode", "none"])
                    .output();
            }
        }
        if let Some(writer) = &self.kde_bin {
            let reader = writer.replacen("kwrite", "kread", 1);
            let config = ["--file", "kioslaverc", "--group", "Proxy Settings", "--key"];
            let expected_http = format!("http://{} {}", self.addr, self.http_port);
            let http_owned = ["httpProxy", "httpsProxy"].into_iter().any(|key| {
                Command::new(&reader)
                    .args(config)
                    .arg(key)
                    .output()
                    .is_ok_and(|out| {
                        out.status.success()
                            && String::from_utf8_lossy(&out.stdout).trim() == expected_http
                    })
            });
            let socks_owned = self.socks_configured
                && self.socks_port.is_some_and(|sp| {
                    let expected_socks = format!("socks://{} {sp}", self.addr);
                    Command::new(&reader)
                        .args(config)
                        .arg("socksProxy")
                        .output()
                        .is_ok_and(|out| {
                            out.status.success()
                                && String::from_utf8_lossy(&out.stdout).trim() == expected_socks
                        })
                });
            if http_owned || socks_owned {
                let _ = Command::new(writer)
                    .args(config)
                    .args(["ProxyType", "0"])
                    .output();
                notify_kde_reload();
            }
        }
        if self.systemd_env_configured && command_exists("systemctl") {
            let expected = format!("http://{}:{}", self.addr, self.http_port);
            let owned = Command::new("systemctl")
                .args(["--user", "show-environment"])
                .output()
                .ok()
                .filter(|out| out.status.success())
                .is_some_and(|out| {
                    let text = String::from_utf8_lossy(&out.stdout);
                    systemd_env_matches_proxy(&text, &expected)
                });
            if owned {
                let _ = Command::new("systemctl")
                    .args([
                        "--user",
                        "unset-environment",
                        "HTTP_PROXY",
                        "HTTPS_PROXY",
                        "http_proxy",
                        "https_proxy",
                        "NO_PROXY",
                        "no_proxy",
                    ])
                    .output();
            }
        }
    }
}

pub fn clear_all_linux_proxies() -> Result<()> {
    if command_exists("gsettings") {
        let _ = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "none"])
            .output();
    }
    if let Some(kbin) = detect_kde_writer_for_cleanup() {
        let _ = Command::new(kbin)
            .args([
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                "ProxyType",
                "0",
            ])
            .output();
        notify_kde_reload();
    }
    if command_exists("systemctl") {
        let _ = Command::new("systemctl")
            .args([
                "--user",
                "unset-environment",
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "http_proxy",
                "https_proxy",
                "NO_PROXY",
                "no_proxy",
            ])
            .output();
    }
    Ok(())
}

pub fn print_linux_proxy_status() {
    println!("\n=== Linux Desktop Proxy Integration ===");
    if command_exists("gsettings") {
        let mode = Command::new("gsettings")
            .args(["get", "org.gnome.system.proxy", "mode"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "<unavailable>".into());
        println!("GNOME proxy mode          : {mode}");
    }
    if command_exists("systemctl") {
        let env_out = Command::new("systemctl")
            .args(["--user", "show-environment"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let https_val = env_out
            .lines()
            .find_map(|l| l.strip_prefix("HTTPS_PROXY="))
            .unwrap_or("<unset>");
        println!("systemd user HTTPS_PROXY  : {https_val}");
    }
}

fn configure_gnome_proxy(
    addr: &str,
    http_port: &str,
    socks_port: Option<u16>,
    ignore_hosts: &str,
) -> bool {
    if !command_exists("gsettings") {
        return false;
    }
    let probe = Command::new("gsettings")
        .args(["get", "org.gnome.system.proxy", "mode"])
        .output();
    if !matches!(probe, Ok(ref o) if o.status.success()) {
        return false;
    }

    let _ = Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.http", "host", addr])
        .output();
    let _ = Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.http", "port", http_port])
        .output();
    let _ = Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.http", "enabled", "true"])
        .output();
    let _ = Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.https", "host", addr])
        .output();
    let _ = Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.https", "port", http_port])
        .output();

    if let Some(sp) = socks_port {
        let sp_str = sp.to_string();
        let _ = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.socks", "host", addr])
            .output();
        let _ = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.socks", "port", &sp_str])
            .output();
    } else {
        let _ = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.socks", "host", ""])
            .output();
        let _ = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.socks", "port", "0"])
            .output();
    }

    let _ = Command::new("gsettings")
        .args([
            "set",
            "org.gnome.system.proxy",
            "ignore-hosts",
            ignore_hosts,
        ])
        .output();
    let res = Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy", "mode", "manual"])
        .output();

    matches!(res, Ok(o) if o.status.success())
}

fn find_kde_writer_bin() -> Option<String> {
    for candidate in ["kwriteconfig6", "kwriteconfig5"] {
        if command_exists(candidate) {
            return Some(candidate.to_string());
        }
    }
    None
}

fn detect_kde_writer() -> Option<String> {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !desktop.contains("kde") && !desktop.contains("plasma") {
        return None;
    }
    find_kde_writer_bin()
}

fn kioslaverc_exists_in(xdg_config_home: Option<&Path>, home: Option<&Path>) -> bool {
    let xdg_exists = xdg_config_home
        .filter(|dir| !dir.as_os_str().is_empty())
        .is_some_and(|dir| dir.join("kioslaverc").exists());
    if xdg_exists {
        return true;
    }
    home.filter(|h| !h.as_os_str().is_empty())
        .is_some_and(|h| h.join(".config").join("kioslaverc").exists())
}

fn kioslaverc_exists() -> bool {
    let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let home = std::env::var_os("HOME").map(PathBuf::from);
    kioslaverc_exists_in(xdg.as_deref(), home.as_deref())
}

fn detect_kde_writer_for_cleanup() -> Option<String> {
    if let Some(kbin) = detect_kde_writer() {
        return Some(kbin);
    }
    if kioslaverc_exists() {
        find_kde_writer_bin()
    } else {
        None
    }
}

fn configure_kde_proxy(
    kbin: &str,
    addr: &str,
    http_port: u16,
    socks_port: Option<u16>,
    no_proxy_csv: &str,
) {
    let http_val = format!("http://{addr} {http_port}");
    for (k, v) in [
        ("ProxyType", "1"),
        ("httpProxy", http_val.as_str()),
        ("httpsProxy", http_val.as_str()),
        ("NoProxyFor", no_proxy_csv),
    ] {
        let _ = Command::new(kbin)
            .args([
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                k,
                v,
            ])
            .output();
    }
    if let Some(sp) = socks_port {
        let socks_val = format!("socks://{addr} {sp}");
        let _ = Command::new(kbin)
            .args([
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                "socksProxy",
                &socks_val,
            ])
            .output();
    }
    notify_kde_reload();
}

fn notify_kde_reload() {
    if command_exists("dbus-send") {
        let _ = Command::new("dbus-send")
            .args([
                "--type=signal",
                "/KIO/Scheduler",
                "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                "string:",
            ])
            .output();
    }
}

fn set_systemd_user_env(proxy_url: &str, no_proxy: &str) -> bool {
    if !command_exists("systemctl") {
        return false;
    }
    let res = Command::new("systemctl")
        .args([
            "--user",
            "set-environment",
            &format!("HTTP_PROXY={proxy_url}"),
            &format!("HTTPS_PROXY={proxy_url}"),
            &format!("http_proxy={proxy_url}"),
            &format!("https_proxy={proxy_url}"),
            &format!("NO_PROXY={no_proxy}"),
            &format!("no_proxy={no_proxy}"),
        ])
        .output();
    let _ = Command::new("systemctl")
        .args(["--user", "unset-environment", "ALL_PROXY", "all_proxy"])
        .output();
    matches!(res, Ok(o) if o.status.success())
}

fn systemd_env_matches_proxy(env_output: &str, expected_proxy_url: &str) -> bool {
    env_output.lines().any(|line| {
        ["HTTP_PROXY=", "HTTPS_PROXY=", "http_proxy=", "https_proxy="]
            .into_iter()
            .any(|prefix| line.strip_prefix(prefix) == Some(expected_proxy_url))
    })
}

fn build_gsettings_ignore_hosts(extra: &[String]) -> String {
    let mut items: Vec<String> = vec![
        "localhost".into(),
        "127.0.0.0/8".into(),
        "::1".into(),
        "10.0.0.0/8".into(),
        "172.16.0.0/12".into(),
        "192.168.0.0/16".into(),
        "169.254.0.0/16".into(),
        ".local".into(),
        ".gov.tr".into(),
        ".isbank.com.tr".into(),
    ];
    for entry in extra {
        let clean = entry.trim().trim_start_matches('*');
        if !clean.is_empty() && !items.iter().any(|x| x.eq_ignore_ascii_case(clean)) {
            items.push(clean.to_string());
        }
    }
    let quoted: Vec<String> = items
        .iter()
        .map(|s| format!("'{}'", s.replace('\\', "\\\\").replace('\'', "")))
        .collect();
    format!("[{}]", quoted.join(", "))
}

fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && (meta.permissions().mode() & 0o111) != 0)
}

fn command_exists_in_path(bin: &str, path_var: Option<&std::ffi::OsStr>) -> bool {
    if bin.is_empty() || bin.contains('\0') {
        return false;
    }
    if bin.contains('/') {
        return is_executable_file(Path::new(bin));
    }
    let Some(path_var) = path_var else {
        return false;
    };
    std::env::split_paths(path_var)
        .filter(|dir| !dir.as_os_str().is_empty())
        .any(|dir| is_executable_file(&dir.join(bin)))
}

pub fn command_exists(bin: &str) -> bool {
    let path_var = std::env::var_os("PATH");
    command_exists_in_path(bin, path_var.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn detects_kioslaverc_in_home_or_xdg_config_home() {
        let root =
            std::env::temp_dir().join(format!("vdpi-kioslaverc-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let home_dir = root.join("home");
        let home_cfg = home_dir.join(".config");
        fs::create_dir_all(&home_cfg).unwrap();

        assert!(!kioslaverc_exists_in(None, Some(&home_dir)));

        fs::write(
            home_cfg.join("kioslaverc"),
            "[Proxy Settings]\nProxyType=1\n",
        )
        .unwrap();
        assert!(kioslaverc_exists_in(None, Some(&home_dir)));

        let xdg_dir = root.join("xdg");
        fs::create_dir_all(&xdg_dir).unwrap();
        assert!(!kioslaverc_exists_in(Some(&xdg_dir), None));

        fs::write(
            xdg_dir.join("kioslaverc"),
            "[Proxy Settings]\nProxyType=1\n",
        )
        .unwrap();
        assert!(kioslaverc_exists_in(Some(&xdg_dir), None));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn pure_rust_command_exists_scans_path_without_shell() {
        let root =
            std::env::temp_dir().join(format!("vdpi-cmd-exists-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let bin_dir = root.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();

        let exec_file = bin_dir.join("mytool");
        fs::write(&exec_file, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&exec_file, fs::Permissions::from_mode(0o755)).unwrap();

        let non_exec = bin_dir.join("readme");
        fs::write(&non_exec, "not executable").unwrap();
        fs::set_permissions(&non_exec, fs::Permissions::from_mode(0o644)).unwrap();

        let dir_as_bin = bin_dir.join("subdir");
        fs::create_dir_all(&dir_as_bin).unwrap();
        fs::set_permissions(&dir_as_bin, fs::Permissions::from_mode(0o755)).unwrap();

        let path_env = OsString::from(bin_dir.as_os_str());
        assert!(command_exists_in_path("mytool", Some(&path_env)));
        assert!(command_exists_in_path(
            exec_file.to_str().unwrap(),
            Some(&path_env)
        ));
        assert!(!command_exists_in_path("readme", Some(&path_env)));
        assert!(!command_exists_in_path("subdir", Some(&path_env)));
        assert!(!command_exists_in_path("missing", Some(&path_env)));
        assert!(!command_exists_in_path("", Some(&path_env)));
        assert!(!command_exists_in_path("mytool; echo pwn", Some(&path_env)));
        assert!(!command_exists_in_path("mytool", None));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn build_gsettings_ignore_hosts_escapes_backslashes_and_strips_quotes() {
        let result = build_gsettings_ignore_hosts(&[
            "foo\\bar".to_string(),
            "baz\\".to_string(),
            "qux'evil".to_string(),
        ]);
        assert!(result.contains("'foo\\\\bar'"));
        assert!(result.contains("'baz\\\\'"));
        assert!(result.contains("'quxevil'"));
    }

    #[test]
    fn systemd_env_ownership_matches_exact_proxy_url() {
        let env = "PATH=/usr/bin\nHTTP_PROXY=http://127.0.0.1:8080\nNO_PROXY=localhost\n";
        assert!(systemd_env_matches_proxy(env, "http://127.0.0.1:8080"));
        assert!(!systemd_env_matches_proxy(env, "http://127.0.0.1:9090"));
    }
}
