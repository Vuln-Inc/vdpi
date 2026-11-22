use crate::{
    clear_engine_cache, engine_version, push_packet, run_doctor_json, snapshot_json, start_tunnel,
    stop_tunnel, IosConfig, PacketCallback, WritePacketFn,
};
use std::ffi::{c_char, c_void, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn into_c_string(value: impl Into<String>) -> *mut c_char {
    let sanitized = value.into().replace('\0', " ");
    CString::new(sanitized)
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

unsafe fn read_c_str(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    CStr::from_ptr(ptr).to_string_lossy().into_owned()
}

/// Starts the iOS TUN engine. Returns NULL on success, or an owned error string on failure.
///
/// # Safety
/// - `config_json` may be NULL or a valid NUL-terminated UTF-8 C string.
/// - `write_cb` must be a valid function pointer safe to invoke from background threads.
/// - `user_ctx` must remain valid until `vdpi_ios_stop()` returns.
#[no_mangle]
pub unsafe extern "C" fn vdpi_ios_start(
    config_json: *const c_char,
    write_cb: Option<WritePacketFn>,
    user_ctx: *mut c_void,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(func) = write_cb else {
            return Some("missing write_cb packet callback".to_string());
        };
        let raw_cfg = read_c_str(config_json);
        let cfg = match IosConfig::from_json_str(&raw_cfg) {
            Ok(c) => c,
            Err(e) => return Some(format!("invalid config JSON: {e}")),
        };
        let callback = PacketCallback { func, user_ctx };
        match start_tunnel(cfg, callback) {
            Ok(()) => None,
            Err(e) => Some(format!("{e:#}")),
        }
    }));

    match result {
        Ok(None) => std::ptr::null_mut(),
        Ok(Some(err)) => into_c_string(err),
        Err(_) => into_c_string("native iOS engine panicked during start"),
    }
}

/// Pushes a single raw IPv4/IPv6 packet from `NEPacketTunnelFlow` into the engine.
///
/// # Safety
/// - `data` must point to at least `len` readable bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn vdpi_ios_push_packet(data: *const u8, len: usize) -> bool {
    if data.is_null() || !(20..=65535).contains(&len) {
        return false;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let slice = std::slice::from_raw_parts(data, len);
        push_packet(slice)
    }))
    .unwrap_or(false)
}

#[no_mangle]
pub extern "C" fn vdpi_ios_stop() {
    let _ = catch_unwind(AssertUnwindSafe(stop_tunnel));
}

#[no_mangle]
pub extern "C" fn vdpi_ios_clear_cache() {
    let _ = catch_unwind(AssertUnwindSafe(clear_engine_cache));
}

#[no_mangle]
pub extern "C" fn vdpi_ios_snapshot_json() -> *mut c_char {
    let payload = catch_unwind(AssertUnwindSafe(snapshot_json))
        .unwrap_or_else(|_| r#"{"running":false}"#.to_string());
    into_c_string(payload)
}

/// Runs live DoH and rustls TLS 1.3/1.2 diagnostics and returns a JSON report string.
///
/// # Safety
/// - `config_json` may be NULL or a valid NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn vdpi_ios_run_doctor_json(config_json: *const c_char) -> *mut c_char {
    let payload = catch_unwind(AssertUnwindSafe(|| {
        let raw_cfg = read_c_str(config_json);
        run_doctor_json(&raw_cfg)
    }))
    .unwrap_or_else(|_| r#"{"ok":false,"checks":[]}"#.to_string());
    into_c_string(payload)
}

#[no_mangle]
pub extern "C" fn vdpi_ios_version() -> *mut c_char {
    let ver = catch_unwind(AssertUnwindSafe(engine_version)).unwrap_or(env!("CARGO_PKG_VERSION"));
    into_c_string(ver)
}

/// Frees a string returned by `vdpi_ios_*`. Safe to call with NULL.
///
/// # Safety
/// - `ptr` must be NULL or a pointer previously returned by this crate and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn vdpi_ios_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(CString::from_raw(ptr));
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;
    use vdpi::dns::{decode_dns_response, encode_dns_query};

    struct CaptureState {
        packets: Mutex<Vec<(u8, Vec<u8>)>>,
        notify: Condvar,
    }

    unsafe extern "C" fn capture_cb(
        data: *const u8,
        len: usize,
        family: u8,
        user_ctx: *mut c_void,
    ) {
        let state = &*(user_ctx as *const CaptureState);
        let bytes = std::slice::from_raw_parts(data, len).to_vec();
        let mut guard = state.packets.lock().unwrap();
        guard.push((family, bytes));
        state.notify.notify_all();
    }

    fn take_owned_c_string(ptr: *mut c_char) -> String {
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() };
        unsafe { vdpi_ios_string_free(ptr) };
        s
    }

    #[test]
    fn c_abi_lifecycle_validation_dns_roundtrip_and_clean_stop() {
        // 1. Freeing NULL is a safe no-op, and version returns current crate semver.
        unsafe { vdpi_ios_string_free(std::ptr::null_mut()) };
        assert_eq!(take_owned_c_string(vdpi_ios_version()), engine_version());

        // 2. Reject missing callback cleanly.
        let err_missing_cb = unsafe { vdpi_ios_start(std::ptr::null(), None, std::ptr::null_mut()) };
        let msg = take_owned_c_string(err_missing_cb);
        assert!(msg.contains("callback"));

        // 3. Reject malformed JSON cleanly.
        let bad_json = CString::new("{not-json").unwrap();
        let err_bad_json = unsafe {
            vdpi_ios_start(bad_json.as_ptr(), Some(capture_cb), std::ptr::null_mut())
        };
        let bad_msg = take_owned_c_string(err_bad_json);
        assert!(bad_msg.contains("invalid config JSON"));

        // 4. Reject packet push while stopped.
        assert!(!unsafe { vdpi_ios_push_packet(std::ptr::null(), 0) });

        // 5. Start live tunnel in LowMemory profile, inject IPv4 UDP DNS query for localhost.
        let capture = Arc::new(CaptureState {
            packets: Mutex::new(Vec::new()),
            notify: Condvar::new(),
        });
        let cfg = CString::new(r#"{"enable_doh":false,"block_quic":true,"mtu":1500}"#).unwrap();
        let start_err = unsafe {
            vdpi_ios_start(
                cfg.as_ptr(),
                Some(capture_cb),
                Arc::as_ptr(&capture) as *mut c_void,
            )
        };
        assert!(start_err.is_null(), "expected start success");

        let mut dns_q = encode_dns_query("localhost", 1).unwrap();
        dns_q[0] = 0x13;
        dns_q[1] = 0x37;
        let builder =
            PacketBuilder::ipv4([10, 8, 0, 2], [198, 18, 0, 1], 64).udp(51000, 53);
        let mut pkt = Vec::with_capacity(builder.size(dns_q.len()));
        builder.write(&mut pkt, &dns_q).unwrap();

        assert!(unsafe { vdpi_ios_push_packet(pkt.as_ptr(), pkt.len()) });

        let received = {
            let guard = capture.packets.lock().unwrap();
            let (guard, timeout_res) = capture
                .notify
                .wait_timeout_while(guard, Duration::from_secs(3), |pkts| pkts.is_empty())
                .unwrap();
            assert!(!timeout_res.timed_out(), "timed out waiting for DNS reply");
            guard[0].clone()
        };

        assert_eq!(received.0, 4);
        let sliced = SlicedPacket::from_ip(&received.1).unwrap();
        let TransportSlice::Udp(udp) = sliced.transport.unwrap() else {
            panic!("expected UDP reply");
        };
        assert_eq!(udp.source_port(), 53);
        assert_eq!(udp.destination_port(), 51000);
        let (ips, _) = decode_dns_response(udp.payload(), 1).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);

        // 6. Telemetry snapshot reports running = true & dns_queries >= 1.
        let snap: serde_json::Value =
            serde_json::from_str(&take_owned_c_string(vdpi_ios_snapshot_json())).unwrap();
        assert_eq!(snap["running"], serde_json::Value::Bool(true));
        assert!(snap["dns_queries"].as_u64().unwrap_or(0) >= 1);

        // 7. Clear cache + stop tunnel; verify running = false and no late callbacks.
        vdpi_ios_clear_cache();
        vdpi_ios_stop();

        let stopped_snap: serde_json::Value =
            serde_json::from_str(&take_owned_c_string(vdpi_ios_snapshot_json())).unwrap();
        assert_eq!(stopped_snap["running"], serde_json::Value::Bool(false));
        assert!(!unsafe { vdpi_ios_push_packet(pkt.as_ptr(), pkt.len()) });
    }
}
