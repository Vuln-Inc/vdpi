use crate::config::AndroidConfig;
use crate::{
    clear_engine_cache, engine_version, run_doctor_json, snapshot_json, start_tunnel, stop_tunnel,
};
use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use jni::JNIEnv;
use std::os::unix::io::{FromRawFd, OwnedFd};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn safe_jstring(env: &mut JNIEnv, value: &str) -> jstring {
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
    env.new_string(value)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn read_jstring_safe(env: &mut JNIEnv, input: &JString) -> String {
    if input.is_null() {
        return String::new();
    }
    match env.get_string(input) {
        Ok(s) => s.into(),
        Err(_) => {
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
            String::new()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_vulninc_vdpi_engine_NativeEngine_nativeStart(
    mut env: JNIEnv,
    _class: JClass,
    tun_fd: jint,
    config_json: JString,
) -> jstring {
    // Adopt TUN fd ownership immediately so every error or panic path closes it via Drop.
    let owned_fd = if tun_fd >= 0 {
        Some(unsafe { OwnedFd::from_raw_fd(tun_fd) })
    } else {
        None
    };

    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(fd) = owned_fd else {
            return format!("invalid TUN file descriptor: {tun_fd}");
        };
        let raw_cfg = read_jstring_safe(&mut env, &config_json);
        let cfg = match AndroidConfig::from_json_str(&raw_cfg) {
            Ok(c) => c,
            Err(e) => return format!("invalid config JSON: {e}"),
        };
        match start_tunnel(fd, cfg) {
            Ok(()) => String::new(),
            Err(e) => format!("{e:#}"),
        }
    }));

    let msg = match result {
        Ok(m) => m,
        Err(_) => "native engine panicked during start".to_string(),
    };
    safe_jstring(&mut env, &msg)
}

#[no_mangle]
pub extern "system" fn Java_com_vulninc_vdpi_engine_NativeEngine_nativeStop(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = catch_unwind(AssertUnwindSafe(stop_tunnel));
}

#[no_mangle]
pub extern "system" fn Java_com_vulninc_vdpi_engine_NativeEngine_nativeSnapshotJson(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let payload = catch_unwind(AssertUnwindSafe(snapshot_json))
        .unwrap_or_else(|_| r#"{"running":false}"#.to_string());
    safe_jstring(&mut env, &payload)
}

#[no_mangle]
pub extern "system" fn Java_com_vulninc_vdpi_engine_NativeEngine_nativeRunDoctor(
    mut env: JNIEnv,
    _class: JClass,
    config_json: JString,
) -> jstring {
    let payload = catch_unwind(AssertUnwindSafe(|| {
        let raw_cfg = read_jstring_safe(&mut env, &config_json);
        run_doctor_json(&raw_cfg)
    }))
    .unwrap_or_else(|_| r#"{"ok":false,"checks":[]}"#.to_string());
    safe_jstring(&mut env, &payload)
}

#[no_mangle]
pub extern "system" fn Java_com_vulninc_vdpi_engine_NativeEngine_nativeClearCache(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = catch_unwind(AssertUnwindSafe(clear_engine_cache));
}

#[no_mangle]
pub extern "system" fn Java_com_vulninc_vdpi_engine_NativeEngine_nativeVersion(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let ver = catch_unwind(AssertUnwindSafe(engine_version)).unwrap_or("0.2.5");
    safe_jstring(&mut env, ver)
}
