use crate::{
    clear_engine_cache, engine_version, notify_route_change, push_packet, push_packets,
    run_doctor_json, snapshot_json, start_tunnel, start_tunnel_batched, start_tunnel_fd,
    stop_tunnel, BatchedPacketCallback, IosConfig, PacketCallback, WritePacketFn,
    WritePacketsBatchFn,
};
use std::ffi::{c_char, c_void, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};

const MAX_CONFIG_JSON_BYTES: usize = 256 * 1024;

fn into_c_string(value: impl Into<String>) -> *mut c_char {
    let sanitized = value.into().replace('\0', " ");
    CString::new(sanitized)
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Clears `err_buf` to an empty NUL-terminated string when non-NULL and non-empty.
///
/// # Safety
/// - When `err_buf` is non-NULL and `err_buf_len > 0`, `err_buf` must be writable for at least
///   1 byte.
unsafe fn clear_err_buf(err_buf: *mut c_char, err_buf_len: usize) {
    if !err_buf.is_null() && err_buf_len > 0 {
        *err_buf = 0;
    }
}

/// Writes `msg` into `err_buf` as a NUL-terminated UTF-8 string, truncating on a UTF-8
/// character boundary when `msg` exceeds `err_buf_len - 1` bytes.
///
/// # Safety
/// - When `err_buf` is non-NULL and `err_buf_len > 0`, `err_buf` must point to at least
///   `err_buf_len` writable bytes.
unsafe fn write_err_buf(err_buf: *mut c_char, err_buf_len: usize, msg: &str) {
    if err_buf.is_null() || err_buf_len == 0 {
        return;
    }
    let sanitized = msg.replace('\0', " ");
    let max_bytes = err_buf_len - 1;
    let mut copy_len = sanitized.len().min(max_bytes);
    while copy_len > 0 && !sanitized.is_char_boundary(copy_len) {
        copy_len -= 1;
    }
    if copy_len > 0 {
        std::ptr::copy_nonoverlapping(sanitized.as_ptr(), err_buf.cast::<u8>(), copy_len);
    }
    *err_buf.add(copy_len) = 0;
}

/// Reads a NUL-terminated UTF-8 config string from `ptr`, scanning at most
/// `MAX_CONFIG_JSON_BYTES` bytes so malformed or unterminated pointers cannot trigger
/// an unbounded `CStr::from_ptr` scan.
///
/// Returns `Ok("")` when `ptr` is NULL.
///
/// # Safety
/// - `ptr` must be NULL or point to readable bytes up to the first NUL terminator or
///   `MAX_CONFIG_JSON_BYTES + 1` bytes, whichever comes first.
unsafe fn read_bounded_config_json<'a>(ptr: *const c_char) -> Result<&'a str, &'static str> {
    if ptr.is_null() {
        return Ok("");
    }
    let bytes = ptr.cast::<u8>();
    let mut len = 0usize;
    while len <= MAX_CONFIG_JSON_BYTES {
        if *bytes.add(len) == 0 {
            let slice = std::slice::from_raw_parts(bytes, len);
            return std::str::from_utf8(slice).map_err(|_| "config JSON is not valid UTF-8");
        }
        len += 1;
    }
    Err("config JSON exceeds 256 KiB limit or is not NUL-terminated")
}

/// Starts the iOS TUN engine. Returns NULL on success, or an owned error string on failure.
///
/// # Safety
/// - `config_json` may be NULL or a valid NUL-terminated UTF-8 C string (<= 256 KiB).
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
        let raw_cfg = match read_bounded_config_json(config_json) {
            Ok(s) => s,
            Err(msg) => return Some(msg.to_string()),
        };
        let cfg = match IosConfig::from_json_str(raw_cfg) {
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

/// Starts the high-speed direct-FD iOS TUN engine by taking ownership of a `dup()`'d `utun` fd.
/// Returns `0` on success, or `-1` on failure (writing a NUL-terminated message into `err_buf`).
///
/// # Safety
/// - On Unix, `tun_fd` (when `>= 0`) must be a valid, uniquely owned file descriptor (typically
///   created via `dup()`); ownership transfers to Rust immediately and the fd is closed on stop
///   or startup failure.
/// - `config_json` may be NULL or a valid NUL-terminated UTF-8 C string (<= 256 KiB).
/// - When `err_buf` is non-NULL and `err_buf_len > 0`, `err_buf` must point to at least
///   `err_buf_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn vdpi_ios_start_fd(
    tun_fd: i32,
    config_json: *const c_char,
    err_buf: *mut c_char,
    err_buf_len: usize,
) -> i32 {
    clear_err_buf(err_buf, err_buf_len);
    let result = catch_unwind(AssertUnwindSafe(|| {
        if tun_fd < 0 {
            return Err("invalid TUN file descriptor".to_string());
        }
        // Take ownership immediately on Unix so any config or registration failure closes `tun_fd`.
        #[cfg(unix)]
        let owned_fd = {
            use std::os::unix::io::{FromRawFd, OwnedFd};
            OwnedFd::from_raw_fd(tun_fd)
        };

        let raw_cfg = read_bounded_config_json(config_json).map_err(str::to_string)?;
        let cfg =
            IosConfig::from_json_str(raw_cfg).map_err(|e| format!("invalid config JSON: {e}"))?;

        #[cfg(unix)]
        let start_res = start_tunnel_fd(owned_fd, cfg);
        #[cfg(not(unix))]
        let start_res = start_tunnel_fd(tun_fd, cfg);

        start_res.map_err(|e| format!("{e:#}"))
    }));

    match result {
        Ok(Ok(())) => 0,
        Ok(Err(err)) => {
            write_err_buf(err_buf, err_buf_len, &err);
            -1
        }
        Err(_) => {
            write_err_buf(
                err_buf,
                err_buf_len,
                "native iOS engine panicked during start_fd",
            );
            -1
        }
    }
}

/// Starts the fallback `NEPacketTunnelFlow` iOS TUN engine with batched outbound callbacks
/// delivered on a dedicated OS writer thread (`vdpi-ios-tx`).
/// Returns `0` on success, or `-1` on failure (writing a NUL-terminated message into `err_buf`).
///
/// # Safety
/// - `config_json` may be NULL or a valid NUL-terminated UTF-8 C string (<= 256 KiB).
/// - `write_batch_cb` must be a valid function pointer safe to invoke from a background thread.
/// - `user_ctx` must remain valid until `vdpi_ios_stop()` returns.
/// - When `err_buf` is non-NULL and `err_buf_len > 0`, `err_buf` must point to at least
///   `err_buf_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn vdpi_ios_start_batched(
    config_json: *const c_char,
    write_batch_cb: Option<WritePacketsBatchFn>,
    user_ctx: *mut c_void,
    err_buf: *mut c_char,
    err_buf_len: usize,
) -> i32 {
    clear_err_buf(err_buf, err_buf_len);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(func) = write_batch_cb else {
            return Err("missing write_batch_cb packet callback".to_string());
        };
        let raw_cfg = read_bounded_config_json(config_json).map_err(str::to_string)?;
        let cfg =
            IosConfig::from_json_str(raw_cfg).map_err(|e| format!("invalid config JSON: {e}"))?;
        let callback = BatchedPacketCallback { func, user_ctx };
        start_tunnel_batched(cfg, callback).map_err(|e| format!("{e:#}"))
    }));

    match result {
        Ok(Ok(())) => 0,
        Ok(Err(err)) => {
            write_err_buf(err_buf, err_buf_len, &err);
            -1
        }
        Err(_) => {
            write_err_buf(
                err_buf,
                err_buf_len,
                "native iOS engine panicked during start_batched",
            );
            -1
        }
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

/// Pushes a batch of raw IPv4/IPv6 packets from `NEPacketTunnelFlow` into the engine, locking
/// the inbound channel handle once per batch. Returns the number of packets accepted.
///
/// # Safety
/// - When `count > 0`, `ptrs` must point to `count` readable pointers and `lens` must point to
///   `count` readable lengths.
/// - Each non-NULL `ptrs[i]` with `lens[i] > 0` must point to at least `lens[i]` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn vdpi_ios_push_packets(
    ptrs: *const *const u8,
    lens: *const usize,
    count: usize,
) -> usize {
    if count == 0 || ptrs.is_null() || lens.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let ptr_slice = std::slice::from_raw_parts(ptrs, count);
        let len_slice = std::slice::from_raw_parts(lens, count);
        push_packets(
            ptr_slice
                .iter()
                .zip(len_slice.iter())
                .filter_map(|(&ptr, &len)| {
                    if ptr.is_null() || !(20..=65535).contains(&len) {
                        None
                    } else {
                        Some(std::slice::from_raw_parts(ptr, len))
                    }
                }),
        )
    }))
    .unwrap_or(0)
}

/// Signals an uplink/route change to drain and rebind stale UDP Cone-NAT sockets and clear
/// stale DNS cache entries without wiping persisted adaptive TLS strategies.
#[no_mangle]
pub extern "C" fn vdpi_ios_notify_route_change() {
    let _ = catch_unwind(AssertUnwindSafe(notify_route_change));
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
/// - `config_json` may be NULL or a valid NUL-terminated UTF-8 C string (<= 256 KiB).
#[no_mangle]
pub unsafe extern "C" fn vdpi_ios_run_doctor_json(config_json: *const c_char) -> *mut c_char {
    let payload = catch_unwind(AssertUnwindSafe(|| {
        let raw_cfg = match read_bounded_config_json(config_json) {
            Ok(s) => s,
            Err(_) => return r#"{"ok":false,"checks":[]}"#.to_string(),
        };
        run_doctor_json(raw_cfg)
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
    use crate::VdpiPacketSlice;
    use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
    use std::ffi::CStr;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;
    use vdpi_core::dns::{decode_dns_response, encode_dns_query};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

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

    unsafe extern "C" fn capture_batch_cb(
        packets: *const VdpiPacketSlice,
        count: usize,
        user_ctx: *mut c_void,
    ) {
        let state = &*(user_ctx as *const CaptureState);
        let slices = std::slice::from_raw_parts(packets, count);
        let mut guard = state.packets.lock().unwrap();
        for slice in slices {
            let bytes = std::slice::from_raw_parts(slice.data, slice.len).to_vec();
            guard.push((slice.family, bytes));
        }
        state.notify.notify_all();
    }

    fn take_owned_c_string(ptr: *mut c_char) -> String {
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() };
        unsafe { vdpi_ios_string_free(ptr) };
        s
    }

    fn read_c_buf(buf: &[c_char]) -> String {
        unsafe { CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned() }
    }

    #[test]
    fn c_abi_lifecycle_validation_dns_roundtrip_and_clean_stop() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 1. Freeing NULL is a safe no-op, and version returns current crate semver.
        unsafe { vdpi_ios_string_free(std::ptr::null_mut()) };
        assert_eq!(take_owned_c_string(vdpi_ios_version()), engine_version());

        // 2. Reject missing callback cleanly.
        let err_missing_cb =
            unsafe { vdpi_ios_start(std::ptr::null(), None, std::ptr::null_mut()) };
        let msg = take_owned_c_string(err_missing_cb);
        assert!(msg.contains("callback"));

        // 3. Reject malformed JSON cleanly.
        let bad_json = CString::new("{not-json").unwrap();
        let err_bad_json =
            unsafe { vdpi_ios_start(bad_json.as_ptr(), Some(capture_cb), std::ptr::null_mut()) };
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
        let builder = PacketBuilder::ipv4([10, 8, 0, 2], [198, 18, 0, 1], 64).udp(51000, 53);
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

    #[test]
    fn c_abi_batched_start_push_packets_route_change_and_start_fd_validation() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // 1. Missing batch callback fails cleanly into err_buf.
        let mut err_buf: [c_char; 256] = [0; 256];
        let rc_missing_cb = unsafe {
            vdpi_ios_start_batched(
                std::ptr::null(),
                None,
                std::ptr::null_mut(),
                err_buf.as_mut_ptr(),
                err_buf.len(),
            )
        };
        assert_eq!(rc_missing_cb, -1);
        assert!(read_c_buf(&err_buf).contains("callback"));

        // 2. Malformed JSON truncates cleanly into a tiny err_buf with NUL terminator.
        let bad_json = CString::new("{not-json").unwrap();
        let mut tiny_buf: [c_char; 8] = [88; 8];
        let rc_bad_json = unsafe {
            vdpi_ios_start_batched(
                bad_json.as_ptr(),
                Some(capture_batch_cb),
                std::ptr::null_mut(),
                tiny_buf.as_mut_ptr(),
                tiny_buf.len(),
            )
        };
        assert_eq!(rc_bad_json, -1);
        assert_eq!(tiny_buf[tiny_buf.len() - 1], 0);
        assert_eq!(read_c_buf(&tiny_buf), "invalid");

        // 3. Batch push returns 0 when NULL/empty or stopped.
        assert_eq!(
            unsafe { vdpi_ios_push_packets(std::ptr::null(), std::ptr::null(), 0) },
            0
        );

        // 4. Start batched tunnel with oversized MTU (9000 -> capped to 4064) and push a 2-packet batch.
        let capture = Arc::new(CaptureState {
            packets: Mutex::new(Vec::new()),
            notify: Condvar::new(),
        });
        let cfg = CString::new(r#"{"enable_doh":false,"block_quic":true,"mtu":9000}"#).unwrap();
        err_buf[0] = 90;
        let rc_start = unsafe {
            vdpi_ios_start_batched(
                cfg.as_ptr(),
                Some(capture_batch_cb),
                Arc::as_ptr(&capture) as *mut c_void,
                err_buf.as_mut_ptr(),
                err_buf.len(),
            )
        };
        assert_eq!(
            rc_start,
            0,
            "unexpected start_batched error: {}",
            read_c_buf(&err_buf)
        );
        assert_eq!(err_buf[0], 0);

        let make_dns_pkt = |tx_lo: u8, src_port: u16| -> Vec<u8> {
            let mut dns_q = encode_dns_query("localhost", 1).unwrap();
            dns_q[0] = 0x24;
            dns_q[1] = tx_lo;
            let builder = PacketBuilder::ipv4([10, 8, 0, 2], [198, 18, 0, 1], 64).udp(src_port, 53);
            let mut pkt = Vec::with_capacity(builder.size(dns_q.len()));
            builder.write(&mut pkt, &dns_q).unwrap();
            pkt
        };
        let pkt1 = make_dns_pkt(0x01, 51001);
        let pkt2 = make_dns_pkt(0x02, 51002);
        let ptrs = [pkt1.as_ptr(), pkt2.as_ptr()];
        let lens = [pkt1.len(), pkt2.len()];
        let accepted = unsafe { vdpi_ios_push_packets(ptrs.as_ptr(), lens.as_ptr(), ptrs.len()) };
        assert_eq!(accepted, 2);

        let received = {
            let guard = capture.packets.lock().unwrap();
            let (guard, timeout_res) = capture
                .notify
                .wait_timeout_while(guard, Duration::from_secs(3), |pkts| pkts.len() < 2)
                .unwrap();
            assert!(
                !timeout_res.timed_out(),
                "timed out waiting for batched DNS replies"
            );
            guard.clone()
        };
        for (family, bytes) in &received[..2] {
            assert_eq!(*family, 4);
            let sliced = SlicedPacket::from_ip(bytes).unwrap();
            let TransportSlice::Udp(udp) = sliced.transport.unwrap() else {
                panic!("expected UDP reply");
            };
            assert_eq!(udp.source_port(), 53);
            let (ips, _) = decode_dns_response(udp.payload(), 1).unwrap();
            assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        }

        // 5. Notify route change bumps generation and clears DNS cache while tunnel stays running.
        vdpi_ios_notify_route_change();
        let snap: serde_json::Value =
            serde_json::from_str(&take_owned_c_string(vdpi_ios_snapshot_json())).unwrap();
        assert_eq!(snap["running"], serde_json::Value::Bool(true));
        let events_str = snap["events"].to_string();
        assert!(
            events_str.contains("route change notified"),
            "missing route change event: {events_str}"
        );
        assert!(
            events_str.contains("mtu=4064"),
            "expected MTU cap to 4064 in startup event: {events_str}"
        );

        vdpi_ios_stop();
        assert_eq!(
            unsafe { vdpi_ios_push_packets(ptrs.as_ptr(), lens.as_ptr(), ptrs.len()) },
            0
        );

        // 6. Direct-FD start rejects negative fds cleanly everywhere and runs on Unix.
        let rc_neg =
            unsafe { vdpi_ios_start_fd(-1, std::ptr::null(), err_buf.as_mut_ptr(), err_buf.len()) };
        assert_eq!(rc_neg, -1);
        assert!(read_c_buf(&err_buf).contains("invalid TUN file descriptor"));

        #[cfg(not(unix))]
        {
            let rc_non_unix = unsafe {
                vdpi_ios_start_fd(3, std::ptr::null(), err_buf.as_mut_ptr(), err_buf.len())
            };
            assert_eq!(rc_non_unix, -1);
            assert!(read_c_buf(&err_buf).contains("Unix"));
        }

        #[cfg(unix)]
        {
            use std::os::unix::io::{FromRawFd, OwnedFd};
            let mut fds = [-1i32; 2];
            let sp_rc =
                unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
            assert_eq!(sp_rc, 0);
            let _peer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
            let rc_fd = unsafe {
                vdpi_ios_start_fd(fds[0], cfg.as_ptr(), err_buf.as_mut_ptr(), err_buf.len())
            };
            assert_eq!(
                rc_fd,
                0,
                "unexpected start_fd error: {}",
                read_c_buf(&err_buf)
            );
            let fd_snap: serde_json::Value =
                serde_json::from_str(&take_owned_c_string(vdpi_ios_snapshot_json())).unwrap();
            assert_eq!(fd_snap["running"], serde_json::Value::Bool(true));
            vdpi_ios_notify_route_change();
            vdpi_ios_stop();
            let fd_stopped: serde_json::Value =
                serde_json::from_str(&take_owned_c_string(vdpi_ios_snapshot_json())).unwrap();
            assert_eq!(fd_stopped["running"], serde_json::Value::Bool(false));
        }
    }

    #[test]
    fn bounded_config_json_reader_rejects_oversized_unterminated_and_invalid_utf8() {
        // NULL pointer maps to empty default config string.
        assert_eq!(
            unsafe { read_bounded_config_json(std::ptr::null()) },
            Ok("")
        );

        // Valid NUL-terminated UTF-8 JSON succeeds.
        let valid = CString::new(r#"{"mtu":1400}"#).unwrap();
        assert_eq!(
            unsafe { read_bounded_config_json(valid.as_ptr()) },
            Ok(r#"{"mtu":1400}"#)
        );

        // Exact cap (256 KiB) followed by NUL terminator succeeds.
        let mut exact = vec![b' '; MAX_CONFIG_JSON_BYTES];
        exact.push(0);
        let exact_res = unsafe { read_bounded_config_json(exact.as_ptr().cast::<c_char>()) };
        assert_eq!(exact_res.map(str::len), Ok(MAX_CONFIG_JSON_BYTES));

        // Buffer without a NUL byte within MAX_CONFIG_JSON_BYTES fails without scanning further.
        let oversized = vec![b'a'; MAX_CONFIG_JSON_BYTES + 16];
        let over_err = unsafe { read_bounded_config_json(oversized.as_ptr().cast::<c_char>()) };
        assert!(over_err.is_err());

        // Invalid UTF-8 bytes fail cleanly.
        let bad_utf8: [u8; 3] = [0xff, 0xfe, 0x00];
        let utf8_err = unsafe { read_bounded_config_json(bad_utf8.as_ptr().cast::<c_char>()) };
        assert!(utf8_err.is_err());

        // Public FFI entrypoints reject oversized pointers cleanly.
        let start_err = unsafe {
            vdpi_ios_start(
                oversized.as_ptr().cast::<c_char>(),
                Some(capture_cb),
                std::ptr::null_mut(),
            )
        };
        let start_msg = take_owned_c_string(start_err);
        assert!(start_msg.contains("256 KiB"));

        let doctor_resp = take_owned_c_string(unsafe {
            vdpi_ios_run_doctor_json(oversized.as_ptr().cast::<c_char>())
        });
        assert_eq!(doctor_resp, r#"{"ok":false,"checks":[]}"#);
    }
}
