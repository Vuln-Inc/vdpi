#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn desktop_proxy_is_released_after_the_foreground_process_is_killed() {
    let dir = std::env::temp_dir().join(format!("vdpi-desktop-test-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    struct TestDir(std::path::PathBuf);
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = TestDir(dir.clone());
    let program = dir.join("gsettings");
    fs::write(&program, r#"#!/bin/sh
key="$HOME/$2.$3"
case "$1" in
  get)
    if [ -f "$key" ]; then
      read -r value < "$key"
      printf '%s\n' "$value"
    else
      case "$3" in
        mode) printf "'none'\n" ;;
        ignore-hosts) printf "@as []\n" ;;
        port) printf "0\n" ;;
        enabled) printf "false\n" ;;
        *) printf "''\n" ;;
      esac
    fi
    ;;
  set)
    case "$3" in
      mode|autoconfig-url|host) printf "'%s'\n" "$4" > "$key" ;;
      *) printf '%s\n' "$4" > "$key" ;;
    esac
    ;;
esac
"#).unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_vdpi"))
        .args(["start", "--quiet", "--port", "0", "--socks-port", "0"])
        .env_clear()
        .env("HOME", &dir)
        .env("PATH", &dir)
        .env("VDPI_TEST_TRUSTED_BIN_DIR", &dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mode = dir.join("org.gnome.system.proxy.mode");
    let wait_for = |expected| {
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until {
            if fs::read_to_string(&mode).is_ok_and(|s| s == expected) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    };
    let enabled = wait_for("'auto'\n");
    let _ = child.kill();
    child.wait().unwrap();
    assert!(enabled, "foreground proxy was never enabled");
    assert!(wait_for("'none'\n"), "foreground proxy was not released");
}
