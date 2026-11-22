use crate::config::AndroidConfig;
use crate::{clear_engine_cache, run_doctor_json, snapshot_json, start_tunnel, stop_tunnel, engine_version};
use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use jni::JNIEnv;

fn to_jstring(env: &JNIEnv, value: &str) -> jstring {
    env.new_string(value)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_com_vulninc_vdpi_engine_NativeEngine_nativeStart(
    mut env: JNIEnv,
    _class: JClass,
    tun_fd: jint,
    config_json: JString,
) -> jstring {
    let raw_cfg: String = env
        .get_string(&config_json)
        .map(|s| s.into())
        .unwrap_or_default();

    let cfg = match AndroidConfig::from_json_str(&raw_cfg) {
        Ok(c) => c,
        Err(e) => return to_jstring(&env, &format!("invalid config JSON: {e}")),
    };

    match start_tunnel(tun_fd, cfg) {
        Ok(()) => to_jstring(&env, ""),
        Err(e) => to_jstring(&env, &format!("{e:#}")),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_vulninc_vdpi_engine_NativeEngine_nativeStop(
    _env: JNIEnv,
    _class: JClass,
) {
    stop_tunnel();
}

#[no_mangle]
pub extern "system" fn Java_com_vulninc_vdpi_engine_NativeEngine_nativeSnapshotJson(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    to_jstring(&env, &snapshot_json())
}

#[no_mangle]
pub extern "system" fn Java_com_vulninc_vdpi_engine_NativeEngine_nativeRunDoctor(
    mut env: JNIEnv,
    _class: JClass,
    config_json: JString,
) -> jstring {
    let raw_cfg: String = env
        .get_string(&config_json)
        .map(|s| s.into())
        .unwrap_or_default();
    to_jstring(&env, &run_doctor_json(&raw_cfg))
}

#[no_mangle]
pub extern "system" fn Java_com_vulninc_vdpi_engine_NativeEngine_nativeClearCache(
    _env: JNIEnv,
    _class: JClass,
) {
    clear_engine_cache();
}

#[no_mangle]
pub extern "system" fn Java_com_vulninc_vdpi_engine_NativeEngine_nativeVersion(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    to_jstring(&env, engine_version())
}
