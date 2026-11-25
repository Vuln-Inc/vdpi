#ifndef VDPI_IOS_H
#define VDPI_IOS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Callback invoked by the Rust TUN engine whenever an outbound IP packet is ready
 * to be written back into iOS `NEPacketTunnelFlow`.
 *
 * - `data`: pointer to raw IPv4 or IPv6 packet bytes (valid only during the callback).
 * - `len`: byte length of the packet.
 * - `family`: `4` for IPv4 (`AF_INET`) or `6` for IPv6 (`AF_INET6`).
 * - `user_ctx`: opaque context pointer passed to `vdpi_ios_start`.
 *
 * Guarantee: after `vdpi_ios_stop()` returns, `write_cb` will never be invoked again
 * for the stopped session.
 */
typedef void (*VdpiWritePacketFn)(
    const uint8_t *data,
    size_t len,
    uint8_t family,
    void *user_ctx
);

/**
 * Packet slice descriptor passed to `VdpiWritePacketsBatchFn`.
 *
 * - `data`: pointer to raw IPv4 or IPv6 packet bytes (valid only during the callback).
 * - `len`: byte length of the packet.
 * - `family`: `4` for IPv4 (`AF_INET`) or `6` for IPv6 (`AF_INET6`).
 */
typedef struct VdpiPacketSlice {
    const uint8_t *data;
    size_t len;
    uint8_t family;
} VdpiPacketSlice;

/**
 * Callback invoked on a dedicated OS writer thread (`vdpi-ios-tx`) whenever one or more
 * outbound IP packets are ready to be written back into iOS `NEPacketTunnelFlow`.
 *
 * Guarantee: after `vdpi_ios_stop()` returns, `write_batch_cb` will never be invoked again
 * for the stopped session.
 */
typedef void (*VdpiWritePacketsBatchFn)(
    const VdpiPacketSlice *packets,
    size_t count,
    void *user_ctx
);

/**
 * Starts the iOS TUN engine with `config_json` (UTF-8 JSON matching `TunnelConfig`;
 * NULL or empty string uses defaults).
 *
 * Returns NULL on success, or a newly allocated UTF-8 error message on failure.
 * Any non-NULL return value must be freed with `vdpi_ios_string_free`.
 */
char *vdpi_ios_start(
    const char *config_json,
    VdpiWritePacketFn write_cb,
    void *user_ctx
);

/**
 * Starts the high-speed direct-FD iOS TUN engine by taking ownership of a `dup()`'d
 * `utun` file descriptor (`tun_fd`), setting `O_NONBLOCK`, and registering it directly
 * with Tokio (`AsyncFd<OwnedFd>`) without Swift `[Data]` bridging overhead.
 *
 * On Unix, `tun_fd` ownership transfers to the engine immediately (closed automatically
 * on stop or startup error). Passing `tun_fd < 0` fails immediately.
 *
 * Returns `0` on success, or `-1` on failure (writing a NUL-terminated UTF-8 error
 * message into `err_buf` when `err_buf != NULL && err_buf_len > 0`).
 */
int32_t vdpi_ios_start_fd(
    int32_t tun_fd,
    const char *config_json,
    char *err_buf,
    size_t err_buf_len
);

/**
 * Starts the fallback `NEPacketTunnelFlow` iOS TUN engine with batched outbound delivery
 * on a dedicated OS writer thread (`vdpi-ios-tx`, draining up to 64 packets per callback).
 *
 * Returns `0` on success, or `-1` on failure (writing a NUL-terminated UTF-8 error
 * message into `err_buf` when `err_buf != NULL && err_buf_len > 0`).
 */
int32_t vdpi_ios_start_batched(
    const char *config_json,
    VdpiWritePacketsBatchFn write_batch_cb,
    void *user_ctx,
    char *err_buf,
    size_t err_buf_len
);

/**
 * Pushes a single raw IPv4/IPv6 packet read from `NEPacketTunnelFlow` into the engine.
 * Non-blocking: returns `true` if queued, `false` if the tunnel is stopped or saturated.
 */
bool vdpi_ios_push_packet(const uint8_t *data, size_t len);

/**
 * Pushes a batch of raw IPv4/IPv6 packets read from `NEPacketTunnelFlow` into the engine,
 * acquiring the inbound channel lock once per batch.
 *
 * Returns the number of packets accepted into the inbound channel (`< count` indicates
 * channel backpressure or a stopped tunnel).
 */
size_t vdpi_ios_push_packets(
    const uint8_t *const *ptrs,
    const size_t *lens,
    size_t count
);

/**
 * Signals an uplink or route change (e.g. Wi-Fi <-> Cellular handoff or device wake) to
 * immediately drain and rebind stale UDP Cone-NAT sockets and clear stale DNS caches
 * without wiping learned adaptive TLS strategies.
 */
void vdpi_ios_notify_route_change(void);

/**
 * Stops the active tunnel and waits for the outbound writer task to exit before returning.
 */
void vdpi_ios_stop(void);

/**
 * Clears adaptive TLS strategy caches and DNS caches on the active session.
 */
void vdpi_ios_clear_cache(void);

/**
 * Returns a newly allocated UTF-8 JSON telemetry snapshot (`TelemetrySnapshot`).
 * Must be freed with `vdpi_ios_string_free`.
 */
char *vdpi_ios_snapshot_json(void);

/**
 * Runs live DoH and rustls TLS 1.3/1.2 connectivity diagnostics using `config_json`.
 * Returns a newly allocated UTF-8 JSON `DoctorReport`. Must be freed with `vdpi_ios_string_free`.
 */
char *vdpi_ios_run_doctor_json(const char *config_json);

/**
 * Returns the newly allocated UTF-8 engine semver string.
 * Must be freed with `vdpi_ios_string_free`.
 */
char *vdpi_ios_version(void);

/**
 * Frees any string returned by `vdpi_ios_*` functions. Safe to call with NULL.
 */
void vdpi_ios_string_free(char *ptr);

#ifdef __cplusplus
}
#endif

#endif /* VDPI_IOS_H */
