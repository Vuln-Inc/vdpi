#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(any(target_os = "linux", test))]
fn is_linux_wayland_session(
    xdg_session_type: Option<&str>,
    wayland_display: Option<&std::ffi::OsStr>,
    gdk_backend: Option<&str>,
) -> bool {
    let xdg_is_wayland = xdg_session_type
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("wayland"));
    let wayland_display_set = wayland_display.is_some_and(|value| !value.is_empty());
    let gdk_forced_x11 = gdk_backend
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("x11"));

    xdg_is_wayland || (wayland_display_set && !gdk_forced_x11)
}

#[cfg(target_os = "linux")]
fn apply_linux_webkit_workarounds() {
    let xdg_session_type = std::env::var("XDG_SESSION_TYPE").ok();
    let wayland_display = std::env::var_os("WAYLAND_DISPLAY");
    let gdk_backend = std::env::var("GDK_BACKEND").ok();
    let is_wayland = is_linux_wayland_session(
        xdg_session_type.as_deref(),
        wayland_display.as_deref(),
        gdk_backend.as_deref(),
    );
    let has_nvidia = std::path::Path::new("/proc/driver/nvidia/version").exists();
    let dmabuf_unset = std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none();

    if is_wayland && has_nvidia && dmabuf_unset {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    apply_linux_webkit_workarounds();

    vdpi_desktop_lib::run();
}

#[cfg(test)]
mod tests {
    use super::is_linux_wayland_session;
    use std::ffi::OsStr;

    #[test]
    fn linux_wayland_detection_checks_xdg_session_and_wayland_display() {
        assert!(is_linux_wayland_session(Some("wayland"), None, None));
        assert!(is_linux_wayland_session(Some(" Wayland "), None, Some("x11")));
        assert!(is_linux_wayland_session(
            None,
            Some(OsStr::new("wayland-0")),
            None
        ));
        assert!(is_linux_wayland_session(
            Some("x11"),
            Some(OsStr::new("wayland-0")),
            Some("wayland")
        ));
        assert!(!is_linux_wayland_session(
            None,
            Some(OsStr::new("wayland-0")),
            Some("x11")
        ));
        assert!(!is_linux_wayland_session(
            Some("x11"),
            Some(OsStr::new("wayland-0")),
            Some(" X11 ")
        ));
        assert!(!is_linux_wayland_session(
            Some("x11"),
            None,
            None
        ));
        assert!(!is_linux_wayland_session(
            None,
            Some(OsStr::new("")),
            None
        ));
    }
}
