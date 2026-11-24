use etherparse::{SlicedPacket, TransportSlice};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const IP_PROTO_UDP: u8 = 17;
const IPV6_NEXT_HOP_BY_HOP: u8 = 0;
const IPV6_NEXT_ROUTING: u8 = 43;
const IPV6_NEXT_FRAGMENT: u8 = 44;
const IPV6_NEXT_DEST_OPTS: u8 = 60;
pub(crate) const MAX_IPV6_EXT_HEADERS: usize = 8;

/// Parsed metadata and payload view for a validated inbound IPv4 or IPv6 UDP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboundUdpPacket<'a> {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// Inspects an inbound IPv4 or IPv6 UDP packet, walking standard IPv6 extension headers
/// (Hop-by-Hop `0`, Routing `43`, Fragment `44`, Destination Options `60`) in a bounded
/// loop (`MAX_IPV6_EXT_HEADERS = 8`) with strict bounds checks on every slice access.
pub fn inspect_inbound_udp(pkt: &[u8]) -> Option<InboundUdpPacket<'_>> {
    let version = *pkt.first()? >> 4;
    match version {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            let ihl = usize::from(pkt[0] & 0x0f) * 4;
            if ihl < 20 || pkt.len() < ihl {
                return None;
            }
            let total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
            if total_len < ihl || pkt.len() < total_len {
                return None;
            }
            // Non-initial IPv4 fragments do not carry a UDP header.
            let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
            if (frag & 0x1fff) != 0 {
                return None;
            }
            if pkt[9] != IP_PROTO_UDP {
                return None;
            }
            let body = pkt.get(..total_len)?;
            let udp_hdr = body.get(ihl..ihl.checked_add(8)?)?;
            let src_port = u16::from_be_bytes([udp_hdr[0], udp_hdr[1]]);
            let dst_port = u16::from_be_bytes([udp_hdr[2], udp_hdr[3]]);
            let udp_len = usize::from(u16::from_be_bytes([udp_hdr[4], udp_hdr[5]]));
            let remaining = total_len.checked_sub(ihl)?;
            if udp_len < 8 || udp_len != remaining {
                return None;
            }
            let payload_start = ihl.checked_add(8)?;
            let payload_end = ihl.checked_add(udp_len)?;
            let payload = body.get(payload_start..payload_end)?;
            let src_ip = IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]));
            let dst_ip = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));
            Some(InboundUdpPacket {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                payload,
            })
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            let payload_len = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
            if payload_len == 0 {
                return None;
            }
            let end = 40usize.checked_add(payload_len)?;
            let body = pkt.get(..end)?;

            let mut next_header = body[6];
            let mut offset = 40usize;
            for _ in 0..MAX_IPV6_EXT_HEADERS {
                if next_header == IP_PROTO_UDP {
                    break;
                }
                match next_header {
                    IPV6_NEXT_HOP_BY_HOP | IPV6_NEXT_ROUTING | IPV6_NEXT_DEST_OPTS => {
                        let hdr = body.get(offset..offset.checked_add(2)?)?;
                        let hdr_len = (usize::from(hdr[1]) + 1).checked_mul(8)?;
                        let next_offset = offset.checked_add(hdr_len)?;
                        if next_offset > end {
                            return None;
                        }
                        next_header = hdr[0];
                        offset = next_offset;
                    }
                    IPV6_NEXT_FRAGMENT => {
                        let hdr = body.get(offset..offset.checked_add(8)?)?;
                        let frag_field = u16::from_be_bytes([hdr[2], hdr[3]]);
                        // Only initial fragments (fragment offset == 0) can carry a UDP header.
                        if (frag_field & 0xfff8) != 0 {
                            return None;
                        }
                        next_header = hdr[0];
                        offset = offset.checked_add(8)?;
                    }
                    _ => return None,
                }
            }

            if next_header != IP_PROTO_UDP {
                return None;
            }

            let udp_hdr = body.get(offset..offset.checked_add(8)?)?;
            let src_port = u16::from_be_bytes([udp_hdr[0], udp_hdr[1]]);
            let dst_port = u16::from_be_bytes([udp_hdr[2], udp_hdr[3]]);
            let udp_len = usize::from(u16::from_be_bytes([udp_hdr[4], udp_hdr[5]]));
            let remaining = end.checked_sub(offset)?;
            if udp_len < 8 || udp_len != remaining {
                return None;
            }
            let payload_start = offset.checked_add(8)?;
            let payload_end = offset.checked_add(udp_len)?;
            let payload = body.get(payload_start..payload_end)?;
            let src_bytes: [u8; 16] = body.get(8..24)?.try_into().ok()?;
            let dst_bytes: [u8; 16] = body.get(24..40)?.try_into().ok()?;
            Some(InboundUdpPacket {
                src_ip: IpAddr::V6(Ipv6Addr::from(src_bytes)),
                dst_ip: IpAddr::V6(Ipv6Addr::from(dst_bytes)),
                src_port,
                dst_port,
                payload,
            })
        }
        _ => None,
    }
}

/// Validates an inbound IP packet read from TUN *before* feeding it into `netstack-smoltcp`.
/// Critically, `netstack-smoltcp`'s `udp::ReadHalf` terminates its Stream (returns `None`)
/// on any fragmented, IPv6 jumbogram (`payload_length == 0`), or malformed UDP packet;
/// filtering them here keeps UDP & DNS alive.
pub fn is_valid_inbound_tun_packet(pkt: &[u8]) -> bool {
    if pkt.len() < 20 {
        return false;
    }
    let version = pkt[0] >> 4;
    if version != 4 && version != 6 {
        return false;
    }
    if version == 6 {
        if pkt.len() < 40 {
            return false;
        }
        // Reject IPv6 payload_length == 0 (jumbogram / malformed) which etherparse accepts
        // differently from smoltcp and would terminate netstack-smoltcp's udp::ReadHalf.
        let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]);
        if payload_len == 0 || pkt.len() < 40 + usize::from(payload_len) {
            return false;
        }
    }
    let Ok(sliced) = SlicedPacket::from_ip(pkt) else {
        return false;
    };
    if sliced.is_ip_payload_fragmented() {
        return false;
    }
    if let Some(TransportSlice::Udp(udp)) = &sliced.transport {
        let declared = usize::from(udp.length());
        let actual = 8 + udp.payload().len();
        if declared < 8 || declared != actual {
            return false;
        }
        if inspect_inbound_udp(pkt).is_none() {
            return false;
        }
    }
    true
}

/// Builds a truncated (`TC=1`) UDP/53 DNS reply when the full DoH answer exceeds the TUN MTU,
/// prompting the client to retry cleanly over TCP/53 instead of timing out.
pub(crate) fn build_truncated_dns_reply(query: &[u8], full_resp: &[u8]) -> Vec<u8> {
    if full_resp.len() < 12 {
        return full_resp.to_vec();
    }
    let mut out = Vec::with_capacity(query.len().clamp(12, 512));
    out.extend_from_slice(&full_resp[..12]);
    // Set TC (bit 9 of flags = 0x02 in byte 2) and zero AN/NS/AR counts.
    out[2] |= 0x02;
    out[6..12].fill(0);
    // Preserve the question section from the original query when present.
    if query.len() > 12 {
        out[4] = query[4];
        out[5] = query[5];
        out.extend_from_slice(&query[12..query.len().min(512)]);
    } else {
        out[4] = 0;
        out[5] = 0;
    }
    out
}

/// Detects whether a UDP/443 payload looks like QUIC traffic (including RFC 9000 Long Header
/// `0xc0`, RFC 9287 Greased Fixed-Bit Long Header `0x80`, and Short-Header 1-RTT packets).
/// When `block_quic` is enabled on a mobile TUN, dropping *all* non-empty UDP/443 datagrams for
/// desync-eligible hosts prevents half-open or migrated QUIC sessions that otherwise trigger
/// Chrome `ERR_QUIC_PROTOCOL_ERROR` instead of a clean TCP/TLS fallback.
pub fn is_blocked_quic_udp(dst_port: u16, payload: &[u8]) -> bool {
    dst_port == 443 && !payload.is_empty()
}

pub(crate) fn max_udp_payload_for_mtu(mtu: usize, is_ipv4: bool) -> usize {
    let overhead = if is_ipv4 { 20 + 8 } else { 40 + 8 };
    mtu.saturating_sub(overhead)
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use vdpi::dns::encode_dns_query;

    fn build_ipv4_udp(
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let builder =
            PacketBuilder::ipv4(src_ip.octets(), dst_ip.octets(), 64).udp(src_port, dst_port);
        let mut out = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut out, payload).unwrap();
        out
    }

    fn build_ipv6_with_ext_headers(
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        first_next: u8,
        ext_headers: &[u8],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = (8 + payload.len()) as u16;
        let payload_len = (ext_headers.len() + 8 + payload.len()) as u16;
        let mut pkt = Vec::with_capacity(40 + usize::from(payload_len));
        pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&payload_len.to_be_bytes());
        pkt.push(first_next);
        pkt.push(64);
        pkt.extend_from_slice(&src_ip.octets());
        pkt.extend_from_slice(&dst_ip.octets());
        pkt.extend_from_slice(ext_headers);
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&[0x12, 0x34]);
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn inbound_validator_rejects_fragmented_and_malformed_udp() {
        let mut good = build_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            Ipv4Addr::new(10, 0, 0, 2),
            53,
            b"hello",
        );
        assert!(is_valid_inbound_tun_packet(&good));

        good[24] = 0x05;
        good[25] = 0xdc;
        assert!(!is_valid_inbound_tun_packet(&good));

        let mut frag = build_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            Ipv4Addr::new(10, 0, 0, 2),
            53,
            b"hello",
        );
        frag[6] |= 0x20;
        assert!(!is_valid_inbound_tun_packet(&frag));

        assert!(!is_valid_inbound_tun_packet(&[0x00, 0x01, 0x02]));
    }

    #[test]
    fn quic_udp_443_blocker_blocks_standard_greased_and_short_header_packets_only_on_port_443() {
        assert!(is_blocked_quic_udp(443, &[0xc0; 1200]));
        // RFC 9287 Greased QUIC bit (fixed bit 0x40 cleared -> 0x80)
        assert!(is_blocked_quic_udp(443, &[0x80; 1200]));
        // Migrated 1-RTT QUIC Short-Header packet (< 1000 bytes)
        assert!(is_blocked_quic_udp(443, &[0x40; 64]));
        assert!(!is_blocked_quic_udp(443, &[]));
        // Non-443 UDP (voice, games, DNS) must never be blocked by QUIC rule
        assert!(!is_blocked_quic_udp(50000, &[0xc0; 1200]));
        assert!(!is_blocked_quic_udp(53, &[0x40; 64]));
    }

    #[test]
    fn ipv6_extension_headers_udp_53_dns_and_udp_443_quic_are_inspected() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        // Hop-by-Hop (8 bytes) -> Destination Options (16 bytes) -> UDP/53 DNS query.
        let dns_query = encode_dns_query("example.com", 1).unwrap();
        let mut ext_dns = Vec::new();
        ext_dns.extend_from_slice(&[IPV6_NEXT_DEST_OPTS, 0, 1, 4, 0, 0, 0, 0]);
        ext_dns.extend_from_slice(&[IP_PROTO_UDP, 1, 1, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let dns_pkt = build_ipv6_with_ext_headers(
            src,
            dst,
            IPV6_NEXT_HOP_BY_HOP,
            &ext_dns,
            53001,
            53,
            &dns_query,
        );

        assert!(is_valid_inbound_tun_packet(&dns_pkt));
        let inspected_dns = inspect_inbound_udp(&dns_pkt).expect("expected UDP/53 inspection");
        assert_eq!(inspected_dns.src_ip, IpAddr::V6(src));
        assert_eq!(inspected_dns.dst_ip, IpAddr::V6(dst));
        assert_eq!(inspected_dns.src_port, 53001);
        assert_eq!(inspected_dns.dst_port, 53);
        assert_eq!(inspected_dns.payload, dns_query.as_slice());

        // Destination Options (8 bytes) -> UDP/443 QUIC Initial datagram.
        let quic_payload = [0xc0u8; 1200];
        let ext_quic = [IP_PROTO_UDP, 0, 1, 4, 0, 0, 0, 0];
        let quic_pkt = build_ipv6_with_ext_headers(
            src,
            dst,
            IPV6_NEXT_DEST_OPTS,
            &ext_quic,
            54001,
            443,
            &quic_payload,
        );

        assert!(is_valid_inbound_tun_packet(&quic_pkt));
        let inspected_quic = inspect_inbound_udp(&quic_pkt).expect("expected UDP/443 inspection");
        assert_eq!(inspected_quic.dst_port, 443);
        assert_eq!(inspected_quic.payload.len(), 1200);
        assert!(is_blocked_quic_udp(
            inspected_quic.dst_port,
            inspected_quic.payload
        ));

        // Initial atomic Fragment header (offset == 0, M == 0) -> UDP/443.
        let atomic_frag = [IP_PROTO_UDP, 0, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef];
        let frag_pkt = build_ipv6_with_ext_headers(
            src,
            dst,
            IPV6_NEXT_FRAGMENT,
            &atomic_frag,
            54002,
            443,
            &quic_payload[..64],
        );
        let inspected_frag =
            inspect_inbound_udp(&frag_pkt).expect("expected initial fragment UDP/443 inspection");
        assert_eq!(inspected_frag.dst_port, 443);
        assert_eq!(inspected_frag.payload.len(), 64);
    }

    #[test]
    fn truncated_and_malformed_ipv6_extension_headers_return_none_without_panicking() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        // Empty and undersized packets.
        assert!(inspect_inbound_udp(&[]).is_none());
        assert!(inspect_inbound_udp(&[0x60; 39]).is_none());

        // IPv6 jumbogram (payload_len == 0).
        let mut jumbo = [0u8; 48];
        jumbo[0] = 0x60;
        jumbo[6] = IP_PROTO_UDP;
        assert!(inspect_inbound_udp(&jumbo).is_none());

        // Hop-by-Hop header truncated to 1 byte inside payload_len.
        let mut trunc_hbh = [0u8; 41];
        trunc_hbh[0] = 0x60;
        trunc_hbh[4..6].copy_from_slice(&1u16.to_be_bytes());
        trunc_hbh[6] = IPV6_NEXT_HOP_BY_HOP;
        assert!(inspect_inbound_udp(&trunc_hbh).is_none());

        // Hop-by-Hop claims 48 bytes (hdr_ext_len = 5) inside a 16-byte payload.
        let mut overrun_hbh = [0u8; 56];
        overrun_hbh[0] = 0x60;
        overrun_hbh[4..6].copy_from_slice(&16u16.to_be_bytes());
        overrun_hbh[6] = IPV6_NEXT_HOP_BY_HOP;
        overrun_hbh[40] = IP_PROTO_UDP;
        overrun_hbh[41] = 5;
        assert!(inspect_inbound_udp(&overrun_hbh).is_none());

        // Fragment header truncated to 4 bytes.
        let mut trunc_frag = [0u8; 44];
        trunc_frag[0] = 0x60;
        trunc_frag[4..6].copy_from_slice(&4u16.to_be_bytes());
        trunc_frag[6] = IPV6_NEXT_FRAGMENT;
        assert!(inspect_inbound_udp(&trunc_frag).is_none());

        // Non-initial Fragment header (fragment offset != 0) cannot carry a UDP header.
        let non_initial_frag = [IP_PROTO_UDP, 0, 0x00, 0x08, 0xde, 0xad, 0xbe, 0xef];
        let non_initial_pkt = build_ipv6_with_ext_headers(
            src,
            dst,
            IPV6_NEXT_FRAGMENT,
            &non_initial_frag,
            54003,
            443,
            b"fragment-tail",
        );
        assert!(inspect_inbound_udp(&non_initial_pkt).is_none());

        // Exceeding MAX_IPV6_EXT_HEADERS (9 chained extension headers) returns None.
        let mut deep_ext = Vec::new();
        for idx in 0..9 {
            let next = if idx == 8 {
                IP_PROTO_UDP
            } else {
                IPV6_NEXT_DEST_OPTS
            };
            deep_ext.extend_from_slice(&[next, 0, 1, 4, 0, 0, 0, 0]);
        }
        let deep_pkt = build_ipv6_with_ext_headers(
            src,
            dst,
            IPV6_NEXT_HOP_BY_HOP,
            &deep_ext,
            54004,
            53,
            b"deep",
        );
        assert!(inspect_inbound_udp(&deep_pkt).is_none());
        assert!(!is_valid_inbound_tun_packet(&deep_pkt));

        // Valid Hop-by-Hop followed by a truncated UDP header (only 4 bytes).
        let mut trunc_udp = [0u8; 52];
        trunc_udp[0] = 0x60;
        trunc_udp[4..6].copy_from_slice(&12u16.to_be_bytes());
        trunc_udp[6] = IPV6_NEXT_HOP_BY_HOP;
        trunc_udp[40..48].copy_from_slice(&[IP_PROTO_UDP, 0, 1, 4, 0, 0, 0, 0]);
        assert!(inspect_inbound_udp(&trunc_udp).is_none());
    }
}
