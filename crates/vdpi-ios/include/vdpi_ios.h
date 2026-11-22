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
 * Pushes a single raw IPv4/IPv6 packet read from `NEPacketTunnelFlow` into the engine.
 * Non-blocking: returns `true` if queued, `false` if the tunnel is stopped or saturated.
 */
bool vdpi_ios_push_packet(const uint8_t *data, size_t len);

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
