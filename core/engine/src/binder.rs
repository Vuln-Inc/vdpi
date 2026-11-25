use socket2::SockRef;
use std::fmt;
use std::io;
use std::sync::{Arc, RwLock};

/// Platform-agnostic outbound socket binding contract used in TUN mode so sockets opened by
/// `vdpi` (TCP upstream, UDP Cone-NAT, UDP DNS, DoH) bypass the virtual TUN default route
/// and exit directly via the physical uplink or fwmark policy table.
pub trait OutboundBinder: Send + Sync + fmt::Debug + 'static {
    /// Bind or protect a raw socket BEFORE `connect()` or `bind()`.
    fn bind_socket(&self, sock: SockRef<'_>, is_ipv4: bool) -> io::Result<()>;

    /// Optional human-readable physical NIC name for `/vdpi-health` and TUI display.
    fn physical_nic_name(&self) -> Option<String> {
        None
    }
}

/// Default zero-overhead no-op binder used by Proxy mode and iOS NEPacketTunnelProvider.
#[derive(Debug, Default)]
pub struct NoopBinder;

impl OutboundBinder for NoopBinder {
    #[inline]
    fn bind_socket(&self, _sock: SockRef<'_>, _is_ipv4: bool) -> io::Result<()> {
        Ok(())
    }
}

/// Hot-swappable outbound target used by Desktop TUN backends when Wi-Fi <-> Ethernet
/// switches occur without restarting `vdpi`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboundTarget {
    /// Physical NIC human-readable label (e.g. `"Ethernet"`, `"en0"`, `"eth0"`).
    pub nic_name: Option<String>,
    /// Physical IPv4 interface index (Windows `IP_UNICAST_IF`, macOS `IP_BOUND_IF`).
    pub if_index_v4: Option<u32>,
    /// Physical IPv6 interface index (Windows `IPV6_UNICAST_IF`, macOS `IPV6_BOUND_IF`).
    pub if_index_v6: Option<u32>,
    /// Linux `SO_MARK` fwmark (e.g. `0x5644`).
    pub fwmark: Option<u32>,
    /// Fail closed with `ENETUNREACH` when `true` and no valid physical target is available.
    pub fail_closed: bool,
}

/// Shared, thread-safe dynamic [`OutboundBinder`] backed by an [`OutboundTarget`].
#[derive(Debug, Default)]
pub struct DynamicOutboundBinder {
    target: RwLock<OutboundTarget>,
}

impl DynamicOutboundBinder {
    pub fn new(initial: OutboundTarget) -> Arc<Self> {
        Arc::new(Self {
            target: RwLock::new(initial),
        })
    }

    pub fn update(&self, next: OutboundTarget) {
        let mut guard = self.target.write().unwrap_or_else(|e| e.into_inner());
        *guard = next;
    }

    pub fn snapshot(&self) -> OutboundTarget {
        self.target
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// Windows IPv4 `IP_UNICAST_IF` requires network byte order (`htonl(if_index)`),
/// whereas IPv6 `IPV6_UNICAST_IF` requires host byte order.
#[inline]
pub const fn windows_ipv4_unicast_if_value(if_index: u32) -> u32 {
    if_index.to_be()
}

/// Windows IPv6 `IPV6_UNICAST_IF` expects host byte order.
#[inline]
pub const fn windows_ipv6_unicast_if_value(if_index: u32) -> u32 {
    if_index
}

impl OutboundBinder for DynamicOutboundBinder {
    fn bind_socket(&self, sock: SockRef<'_>, is_ipv4: bool) -> io::Result<()> {
        let tgt = self.target.read().unwrap_or_else(|e| e.into_inner());

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::io::AsRawSocket;
            use windows_sys::Win32::Networking::WinSock::{
                setsockopt, WSAGetLastError, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF,
                IP_UNICAST_IF,
            };

            let if_idx = if is_ipv4 {
                tgt.if_index_v4
            } else {
                tgt.if_index_v6
            };
            let Some(idx) = if_idx.filter(|&i| i != 0) else {
                return if tgt.fail_closed {
                    Err(io::Error::from_raw_os_error(10051)) // WSAENETUNREACH
                } else {
                    Ok(())
                };
            };
            let raw = sock.as_raw_socket() as usize;
            let (level, opt, val) = if is_ipv4 {
                (
                    IPPROTO_IP,
                    IP_UNICAST_IF,
                    windows_ipv4_unicast_if_value(idx),
                )
            } else {
                (
                    IPPROTO_IPV6,
                    IPV6_UNICAST_IF,
                    windows_ipv6_unicast_if_value(idx),
                )
            };
            let rc = unsafe {
                setsockopt(
                    raw,
                    level,
                    opt,
                    (&val as *const u32).cast::<u8>(),
                    std::mem::size_of::<u32>() as i32,
                )
            };
            if rc != 0 {
                return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
            }
            Ok(())
        }

        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsRawFd;
            const IP_BOUND_IF: libc::c_int = 25;
            const IPV6_BOUND_IF: libc::c_int = 125;

            let if_idx = if is_ipv4 {
                tgt.if_index_v4
            } else {
                tgt.if_index_v6
            };
            let Some(idx) = if_idx.filter(|&i| i != 0) else {
                return if tgt.fail_closed {
                    Err(io::Error::from_raw_os_error(libc::ENETUNREACH))
                } else {
                    Ok(())
                };
            };
            let (level, opt) = if is_ipv4 {
                (libc::IPPROTO_IP, IP_BOUND_IF)
            } else {
                (libc::IPPROTO_IPV6, IPV6_BOUND_IF)
            };
            let rc = unsafe {
                libc::setsockopt(
                    sock.as_raw_fd(),
                    level,
                    opt,
                    (&idx as *const u32).cast(),
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            let _ = is_ipv4;
            let nic_name = tgt.nic_name.as_deref().filter(|n| !n.is_empty());
            if let Some(mark) = tgt.fwmark.filter(|&m| m != 0) {
                return match sock.set_mark(mark) {
                    Ok(()) => Ok(()),
                    Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                        if let Some(name) = nic_name {
                            sock.bind_device(Some(name.as_bytes()))
                        } else {
                            Err(err)
                        }
                    }
                    Err(err) => Err(err),
                };
            }
            if let Some(name) = nic_name {
                return sock.bind_device(Some(name.as_bytes()));
            }
            if tgt.fail_closed {
                Err(io::Error::from_raw_os_error(libc::ENETUNREACH))
            } else {
                Ok(())
            }
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            let _ = (sock, is_ipv4);
            if tgt.fail_closed {
                Err(io::Error::new(
                    io::ErrorKind::NetworkUnreachable,
                    "DynamicOutboundBinder unsupported on this platform",
                ))
            } else {
                Ok(())
            }
        }
    }

    fn physical_nic_name(&self) -> Option<String> {
        self.target
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .nic_name
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_unicast_if_byte_order_matches_win32_spec() {
        assert_eq!(windows_ipv4_unicast_if_value(12), 12u32.to_be());
        assert_eq!(windows_ipv6_unicast_if_value(12), 12u32);
    }

    #[test]
    fn dynamic_binder_updates_and_snapshots_cleanly() {
        let binder = DynamicOutboundBinder::new(OutboundTarget {
            nic_name: Some("Ethernet".to_string()),
            if_index_v4: Some(7),
            if_index_v6: Some(7),
            fwmark: None,
            fail_closed: true,
        });
        assert_eq!(binder.physical_nic_name().as_deref(), Some("Ethernet"));
        binder.update(OutboundTarget {
            nic_name: Some("Wi-Fi".to_string()),
            if_index_v4: Some(11),
            if_index_v6: None,
            fwmark: None,
            fail_closed: true,
        });
        let snap = binder.snapshot();
        assert_eq!(snap.nic_name.as_deref(), Some("Wi-Fi"));
        assert_eq!(snap.if_index_v4, Some(11));
        assert_eq!(snap.if_index_v6, None);
    }

    #[test]
    fn dynamic_binder_recovers_from_poisoned_rwlock() {
        let binder = DynamicOutboundBinder::new(OutboundTarget {
            nic_name: Some("eth0".to_string()),
            if_index_v4: Some(3),
            if_index_v6: None,
            fwmark: Some(0x5644),
            fail_closed: true,
        });
        let b = Arc::clone(&binder);
        let _ = std::thread::spawn(move || {
            let _guard = b.target.write().unwrap();
            panic!("simulated panic while holding binder lock");
        })
        .join();

        assert!(binder.target.is_poisoned());
        let snap = binder.snapshot();
        assert!(snap.fail_closed);
        assert_eq!(snap.nic_name.as_deref(), Some("eth0"));
        assert_eq!(binder.physical_nic_name().as_deref(), Some("eth0"));

        binder.update(OutboundTarget {
            nic_name: Some("wlan0".to_string()),
            if_index_v4: Some(9),
            if_index_v6: None,
            fwmark: None,
            fail_closed: true,
        });
        assert_eq!(binder.snapshot().nic_name.as_deref(), Some("wlan0"));
    }
}
