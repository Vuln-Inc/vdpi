use etherparse::{SlicedPacket, TransportSlice};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const IP_PROTO_ICMP: u8 = 1;
const IP_PROTO_UDP: u8 = 17;
const IP_PROTO_ICMPV6: u8 = 58;
const IPV6_NEXT_HOP_BY_HOP: u8 = 0;
const IPV6_NEXT_ROUTING: u8 = 43;
const IPV6_NEXT_FRAGMENT: u8 = 44;
const IPV6_NEXT_DEST_OPTS: u8 = 60;
const ICMPV4_TYPE_DEST_UNREACHABLE: u8 = 3;
const ICMPV4_CODE_PORT_UNREACHABLE: u8 = 3;
const ICMPV6_TYPE_DEST_UNREACHABLE: u8 = 1;
const ICMPV6_CODE_NO_ROUTE: u8 = 0;
const ICMPV6_CODE_PORT_UNREACHABLE: u8 = 4;
const IPV4_ICMP_MAX_UDP_PAYLOAD_QUOTE: usize = 64;
const IPV6_MIN_MTU: usize = 1280;
const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
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
            // Reject fragmented IPv4 packets (either non-zero offset or MF bit set).
            let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
            if (frag & 0x3fff) != 0 {
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
                    // RFC 8200 Section 4.1: Hop-by-Hop Options may only appear immediately
                    // after the fixed 40-byte IPv6 header.
                    IPV6_NEXT_HOP_BY_HOP if offset != 40 => return None,
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
                        // Only atomic fragments (fragment offset == 0 and M == 0) carry a
                        // complete UDP datagram.
                        if (frag_field & 0xfff9) != 0 {
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

/// Walks the RFC 1035 DNS Question section starting at byte 12 and returns the exact
/// exclusive end offset of the Question section (stripping any trailing Answer, Authority,
/// or Additional / EDNS0 OPT records). Returns `None` if malformed.
fn dns_question_section_end(pkt: &[u8]) -> Option<usize> {
    if pkt.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    let mut pos = 12usize;
    for _ in 0..qdcount {
        loop {
            let label_len = *pkt.get(pos)?;
            if label_len == 0 {
                pos = pos.checked_add(1)?;
                break;
            }
            if (label_len & 0xc0) == 0xc0 {
                // RFC 1035 compression pointer (2 bytes) terminates the QNAME.
                let next_pos = pos.checked_add(2)?;
                if next_pos > pkt.len() {
                    return None;
                }
                pos = next_pos;
                break;
            }
            if (label_len & 0xc0) != 0 {
                return None;
            }
            let next_pos = pos.checked_add(1)?.checked_add(usize::from(label_len))?;
            if next_pos > pkt.len() {
                return None;
            }
            pos = next_pos;
        }
        // QTYPE (2 bytes) + QCLASS (2 bytes)
        let next_pos = pos.checked_add(4)?;
        if next_pos > pkt.len() {
            return None;
        }
        pos = next_pos;
    }
    Some(pos)
}

/// Builds a truncated (`TC=1`) UDP/53 DNS reply when the full DoH answer exceeds the TUN MTU,
/// prompting the client to retry cleanly over TCP/53 instead of timing out.
///
/// Copies only the validated DNS Question section from `query` (stripping trailing EDNS0 OPT
/// or additional bytes so `ARCOUNT=0` remains wire-valid).
pub(crate) fn build_truncated_dns_reply(query: &[u8], full_resp: &[u8]) -> Vec<u8> {
    if full_resp.len() < 12 {
        return full_resp.to_vec();
    }
    let q_end = dns_question_section_end(query).filter(|&end| end <= 512);
    let out_cap = q_end.unwrap_or(12);
    let mut out = Vec::with_capacity(out_cap);
    out.extend_from_slice(&full_resp[..12]);
    // Set TC (bit 9 of flags = 0x02 in byte 2) and zero AN/NS/AR counts.
    out[2] |= 0x02;
    out[6..12].fill(0);
    // Preserve only the validated question section from the original query when present.
    if let Some(end) = q_end.filter(|&end| end > 12) {
        out[4] = query[4];
        out[5] = query[5];
        out.extend_from_slice(&query[12..end]);
    } else {
        out[4] = 0;
        out[5] = 0;
    }
    out
}

/// Returns `true` if `payload` matches an RFC 5389 STUN header:
/// two leading zero bits `(payload[0] & 0xC0) == 0`, length >= 20, and
/// magic cookie `0x2112A442` at bytes `4..8`.
pub fn is_stun_packet(payload: &[u8]) -> bool {
    payload.len() >= 20 && (payload[0] & 0xC0) == 0 && payload[4..8] == STUN_MAGIC_COOKIE
}

/// Detects whether a UDP/443 payload looks like QUIC traffic (including RFC 9000 Long Header
/// `0xc0`, RFC 9287 Greased Fixed-Bit Long Header `0x80`, and Short-Header 1-RTT packets).
/// When `block_quic` is enabled on a mobile TUN, dropping *all* non-empty UDP/443 datagrams for
/// desync-eligible hosts prevents half-open or migrated QUIC sessions that otherwise trigger
/// Chrome `ERR_QUIC_PROTOCOL_ERROR` instead of a clean TCP/TLS fallback.
///
/// RFC 5389 STUN packets (`(payload[0] & 0xC0) == 0`, length >= 20, magic cookie `0x2112A442`
/// at bytes `4..8`) are explicitly exempted so WebRTC TURN-over-UDP/443 is never broken.
pub fn is_blocked_quic_udp(dst_port: u16, payload: &[u8]) -> bool {
    if dst_port != 443 || payload.is_empty() {
        return false;
    }
    if is_stun_packet(payload) {
        return false;
    }
    true
}

fn internet_checksum_partial(mut sum: u32, data: &[u8]) -> u32 {
    let (chunks, remainder) = data.as_chunks::<2>();
    for &chunk in chunks {
        sum += u32::from(u16::from_be_bytes(chunk));
    }
    if let Some(&last) = remainder.first() {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    sum
}

fn finalize_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn internet_checksum(data: &[u8]) -> u16 {
    finalize_checksum(internet_checksum_partial(0, data))
}

fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, icmp_msg: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = internet_checksum_partial(sum, &src.octets());
    sum = internet_checksum_partial(sum, &dst.octets());
    let len_bytes = (icmp_msg.len() as u32).to_be_bytes();
    sum = internet_checksum_partial(sum, &len_bytes);
    sum = internet_checksum_partial(sum, &[0, 0, 0, IP_PROTO_ICMPV6]);
    sum = internet_checksum_partial(sum, icmp_msg);
    finalize_checksum(sum)
}

fn udp_ipv4_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp_segment: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = internet_checksum_partial(sum, &src.octets());
    sum = internet_checksum_partial(sum, &dst.octets());
    sum = internet_checksum_partial(sum, &[0, IP_PROTO_UDP]);
    sum = internet_checksum_partial(sum, &(udp_segment.len() as u16).to_be_bytes());
    sum = internet_checksum_partial(sum, udp_segment);
    let cksum = finalize_checksum(sum);
    if cksum == 0 {
        0xffff
    } else {
        cksum
    }
}

fn udp_ipv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, udp_segment: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = internet_checksum_partial(sum, &src.octets());
    sum = internet_checksum_partial(sum, &dst.octets());
    let len_bytes = (udp_segment.len() as u32).to_be_bytes();
    sum = internet_checksum_partial(sum, &len_bytes);
    sum = internet_checksum_partial(sum, &[0, 0, 0, IP_PROTO_UDP]);
    sum = internet_checksum_partial(sum, udp_segment);
    let cksum = finalize_checksum(sum);
    // RFC 8200 Section 8.1: IPv6 UDP checksum of 0x0000 MUST be transmitted as 0xFFFF.
    if cksum == 0 {
        0xffff
    } else {
        cksum
    }
}

/// Synthesizes a raw IPv4+UDP or IPv6+UDP packet directly for TUN egress with a valid
/// IPv4 header checksum and RFC 768 / RFC 8200 UDP pseudo-header checksum (normalizing
/// a computed checksum of `0` to `0xFFFF`). Returns `None` on IP family mismatch or
/// payload lengths that overflow 16-bit IP/UDP header fields.
pub fn build_udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    match (src, dst) {
        (SocketAddr::V4(src_v4), SocketAddr::V4(dst_v4)) => {
            let udp_len = 8usize.checked_add(payload.len())?;
            let udp_len_u16 = u16::try_from(udp_len).ok()?;
            let total_len = 20usize.checked_add(udp_len)?;
            let total_len_u16 = u16::try_from(total_len).ok()?;

            let mut out = vec![0u8; total_len];
            // IPv4 header (20 bytes, IHL=5, TTL=64, Protocol=UDP)
            out[0] = 0x45;
            out[2..4].copy_from_slice(&total_len_u16.to_be_bytes());
            out[8] = 64;
            out[9] = IP_PROTO_UDP;
            out[12..16].copy_from_slice(&src_v4.ip().octets());
            out[16..20].copy_from_slice(&dst_v4.ip().octets());
            let ip_cksum = internet_checksum(&out[..20]);
            out[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

            // UDP header (8 bytes) + payload
            out[20..22].copy_from_slice(&src_v4.port().to_be_bytes());
            out[22..24].copy_from_slice(&dst_v4.port().to_be_bytes());
            out[24..26].copy_from_slice(&udp_len_u16.to_be_bytes());
            out[28..].copy_from_slice(payload);
            let udp_cksum = udp_ipv4_checksum(*src_v4.ip(), *dst_v4.ip(), &out[20..]);
            out[26..28].copy_from_slice(&udp_cksum.to_be_bytes());

            Some(out)
        }
        (SocketAddr::V6(src_v6), SocketAddr::V6(dst_v6)) => {
            let udp_len = 8usize.checked_add(payload.len())?;
            let udp_len_u16 = u16::try_from(udp_len).ok()?;
            let total_len = 40usize.checked_add(udp_len)?;

            let mut out = vec![0u8; total_len];
            // IPv6 header (40 bytes, Next Header=UDP, Hop Limit=64)
            out[0] = 0x60;
            out[4..6].copy_from_slice(&udp_len_u16.to_be_bytes());
            out[6] = IP_PROTO_UDP;
            out[7] = 64;
            out[8..24].copy_from_slice(&src_v6.ip().octets());
            out[24..40].copy_from_slice(&dst_v6.ip().octets());

            // UDP header (8 bytes) + payload
            out[40..42].copy_from_slice(&src_v6.port().to_be_bytes());
            out[42..44].copy_from_slice(&dst_v6.port().to_be_bytes());
            out[44..46].copy_from_slice(&udp_len_u16.to_be_bytes());
            out[48..].copy_from_slice(payload);
            let udp_cksum = udp_ipv6_checksum(*src_v6.ip(), *dst_v6.ip(), &out[40..]);
            out[46..48].copy_from_slice(&udp_cksum.to_be_bytes());

            Some(out)
        }
        _ => None,
    }
}

fn is_invalid_icmpv4_addr(addr: Ipv4Addr) -> bool {
    addr.is_multicast() || addr.is_broadcast() || addr.is_unspecified()
}

fn is_invalid_icmpv6_addr(addr: Ipv6Addr) -> bool {
    addr.is_multicast() || addr.is_unspecified()
}

fn build_icmpv6_dest_unreachable(
    body: &[u8],
    orig_src: Ipv6Addr,
    orig_dst: Ipv6Addr,
    code: u8,
) -> Option<Vec<u8>> {
    if is_invalid_icmpv6_addr(orig_src) || is_invalid_icmpv6_addr(orig_dst) {
        return None;
    }

    // RFC 4443 Section 2.4(c): quote as much of the invoking packet as possible
    // without exceeding the 1280-byte IPv6 minimum MTU.
    const MAX_QUOTE: usize = IPV6_MIN_MTU - 40 - 8;
    let quote = &body[..body.len().min(MAX_QUOTE)];
    let icmp_len = 8usize.checked_add(quote.len())?;
    let icmp_len_u16 = u16::try_from(icmp_len).ok()?;
    let out_total_len = 40usize.checked_add(icmp_len)?;

    let mut out = vec![0u8; out_total_len];
    // IPv6 header (40 bytes): version=6, traffic class=0, flow label=0
    out[0] = 0x60;
    out[4..6].copy_from_slice(&icmp_len_u16.to_be_bytes());
    out[6] = IP_PROTO_ICMPV6;
    out[7] = 64;
    out[8..24].copy_from_slice(&orig_dst.octets());
    out[24..40].copy_from_slice(&orig_src.octets());

    // RFC 4443 Section 3.1: ICMPv6 Destination Unreachable (Type 1)
    out[40] = ICMPV6_TYPE_DEST_UNREACHABLE;
    out[41] = code;
    out[48..].copy_from_slice(quote);

    let icmp_cksum = icmpv6_checksum(orig_dst, orig_src, &out[40..]);
    out[42..44].copy_from_slice(&icmp_cksum.to_be_bytes());

    Some(out)
}

fn is_icmpv6_error_or_non_initial_fragment(body: &[u8]) -> bool {
    let mut next_header = body[6];
    let mut offset = 40usize;
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        if next_header == IP_PROTO_ICMPV6 {
            // RFC 4443 Section 2.1: ICMPv6 types 0..=127 are error messages.
            return match body.get(offset) {
                Some(&icmp_type) => icmp_type < 128,
                None => true,
            };
        }
        match next_header {
            IPV6_NEXT_HOP_BY_HOP if offset != 40 => return true,
            IPV6_NEXT_HOP_BY_HOP | IPV6_NEXT_ROUTING | IPV6_NEXT_DEST_OPTS => {
                let Some(end_hdr) = offset.checked_add(2) else {
                    return true;
                };
                let Some(hdr) = body.get(offset..end_hdr) else {
                    return true;
                };
                let Some(hdr_len) = (usize::from(hdr[1]) + 1).checked_mul(8) else {
                    return true;
                };
                let Some(next_offset) = offset.checked_add(hdr_len) else {
                    return true;
                };
                if next_offset > body.len() {
                    return true;
                }
                next_header = hdr[0];
                offset = next_offset;
            }
            IPV6_NEXT_FRAGMENT => {
                let Some(end_hdr) = offset.checked_add(8) else {
                    return true;
                };
                let Some(hdr) = body.get(offset..end_hdr) else {
                    return true;
                };
                let frag_field = u16::from_be_bytes([hdr[2], hdr[3]]);
                if (frag_field & 0xfff8) != 0 {
                    return true;
                }
                next_header = hdr[0];
                offset = end_hdr;
            }
            _ => return false,
        }
    }
    // After walking MAX_IPV6_EXT_HEADERS headers, inspect the resulting next_header
    // instead of blindly rejecting valid packets with exactly MAX_IPV6_EXT_HEADERS headers.
    match next_header {
        IP_PROTO_ICMPV6 => match body.get(offset) {
            Some(&icmp_type) => icmp_type < 128,
            None => true,
        },
        IPV6_NEXT_HOP_BY_HOP | IPV6_NEXT_ROUTING | IPV6_NEXT_DEST_OPTS | IPV6_NEXT_FRAGMENT => true,
        _ => false,
    }
}

/// Synthesizes an RFC 792 ICMPv4 Type 3 Code 3 or RFC 4443 ICMPv6 Type 1 Code 4
/// (Port Unreachable) packet for an invoking UDP packet so blocked QUIC/UDP clients
/// immediately receive `ECONNREFUSED` and fall back to TCP/TLS without stalling.
pub fn build_icmp_port_unreachable(invoking_pkt: &[u8]) -> Option<Vec<u8>> {
    let version = *invoking_pkt.first()? >> 4;
    match version {
        4 => {
            if invoking_pkt.len() < 20 {
                return None;
            }
            let ihl = usize::from(invoking_pkt[0] & 0x0f) * 4;
            if ihl < 20 || invoking_pkt.len() < ihl {
                return None;
            }
            let total_len = usize::from(u16::from_be_bytes([invoking_pkt[2], invoking_pkt[3]]));
            if total_len < ihl.checked_add(8)? || invoking_pkt.len() < total_len {
                return None;
            }
            let frag = u16::from_be_bytes([invoking_pkt[6], invoking_pkt[7]]);
            if (frag & 0x1fff) != 0 {
                return None;
            }
            if invoking_pkt[9] != IP_PROTO_UDP {
                return None;
            }

            let orig_src = Ipv4Addr::new(
                invoking_pkt[12],
                invoking_pkt[13],
                invoking_pkt[14],
                invoking_pkt[15],
            );
            let orig_dst = Ipv4Addr::new(
                invoking_pkt[16],
                invoking_pkt[17],
                invoking_pkt[18],
                invoking_pkt[19],
            );
            if is_invalid_icmpv4_addr(orig_src) || is_invalid_icmpv4_addr(orig_dst) {
                return None;
            }

            let max_quote = ihl
                .checked_add(8)?
                .checked_add(IPV4_ICMP_MAX_UDP_PAYLOAD_QUOTE)?;
            let quote_len = total_len.min(max_quote);
            let quote = invoking_pkt.get(..quote_len)?;

            let icmp_len = 8usize.checked_add(quote.len())?;
            let out_total_len = 20usize.checked_add(icmp_len)?;
            let out_total_len_u16 = u16::try_from(out_total_len).ok()?;

            let mut out = vec![0u8; out_total_len];
            // RFC 792 IPv4 header (20 bytes, IHL=5)
            out[0] = 0x45;
            out[2..4].copy_from_slice(&out_total_len_u16.to_be_bytes());
            out[8] = 64;
            out[9] = IP_PROTO_ICMP;
            out[12..16].copy_from_slice(&orig_dst.octets());
            out[16..20].copy_from_slice(&orig_src.octets());

            let ip_cksum = internet_checksum(&out[..20]);
            out[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

            // RFC 792 ICMPv4 Destination Unreachable / Port Unreachable (Type 3, Code 3)
            out[20] = ICMPV4_TYPE_DEST_UNREACHABLE;
            out[21] = ICMPV4_CODE_PORT_UNREACHABLE;
            out[28..].copy_from_slice(quote);

            let icmp_cksum = internet_checksum(&out[20..]);
            out[22..24].copy_from_slice(&icmp_cksum.to_be_bytes());

            Some(out)
        }
        6 => {
            let parsed = inspect_inbound_udp(invoking_pkt)?;
            let (IpAddr::V6(orig_src), IpAddr::V6(orig_dst)) = (parsed.src_ip, parsed.dst_ip)
            else {
                return None;
            };
            let payload_len = usize::from(u16::from_be_bytes([invoking_pkt[4], invoking_pkt[5]]));
            let end = 40usize.checked_add(payload_len)?;
            let body = invoking_pkt.get(..end)?;
            build_icmpv6_dest_unreachable(body, orig_src, orig_dst, ICMPV6_CODE_PORT_UNREACHABLE)
        }
        _ => None,
    }
}

/// Synthesizes an RFC 4443 ICMPv6 Destination Unreachable / No Route to Destination
/// (Type 1, Code 0) packet for an invoking IPv6 packet, triggering instant Happy Eyeballs
/// IPv4 fallback on IPv4-only ISPs.
pub fn build_icmpv6_no_route(invoking_pkt: &[u8]) -> Option<Vec<u8>> {
    if invoking_pkt.len() < 40 || (invoking_pkt[0] >> 4) != 6 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([invoking_pkt[4], invoking_pkt[5]]));
    if payload_len == 0 {
        return None;
    }
    let end = 40usize.checked_add(payload_len)?;
    let body = invoking_pkt.get(..end)?;
    if is_icmpv6_error_or_non_initial_fragment(body) {
        return None;
    }
    let src_bytes: [u8; 16] = body.get(8..24)?.try_into().ok()?;
    let dst_bytes: [u8; 16] = body.get(24..40)?.try_into().ok()?;
    let orig_src = Ipv6Addr::from(src_bytes);
    let orig_dst = Ipv6Addr::from(dst_bytes);
    build_icmpv6_dest_unreachable(body, orig_src, orig_dst, ICMPV6_CODE_NO_ROUTE)
}

/// RFC 9715 / DNS Flag Day 2020 maximum safe internet UDP DNS payload size (1232 bytes),
/// ensuring oversized local TUN MTUs (such as `DESKTOP_MTU = 16384`) never synthesize
/// UDP/53 replies larger than 1232 bytes.
pub(crate) const MAX_DNS_UDP_PAYLOAD: usize = 1232;

pub(crate) fn max_udp_payload_for_mtu(mtu: usize, is_ipv4: bool) -> usize {
    let overhead = if is_ipv4 { 20 + 8 } else { 40 + 8 };
    let ip_limit = if is_ipv4 {
        usize::from(u16::MAX) - 20 - 8
    } else {
        usize::from(u16::MAX) - 8
    };
    mtu.saturating_sub(overhead).min(ip_limit)
}

pub(crate) fn max_dns_udp_payload_for_mtu(mtu: usize, is_ipv4: bool) -> usize {
    max_udp_payload_for_mtu(mtu, is_ipv4).min(MAX_DNS_UDP_PAYLOAD)
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use vdpi_core::dns::encode_dns_query;

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

    fn build_ipv4_tcp_syn(src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&src_ip.octets());
        pkt[16..20].copy_from_slice(&dst_ip.octets());
        let cksum = internet_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&cksum.to_be_bytes());
        // Minimal 20-byte TCP SYN header (src_port=45000, dst_port=443, data_offset=5, SYN)
        pkt[20..22].copy_from_slice(&45000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[32] = 0x50;
        pkt[33] = 0x02;
        pkt
    }

    fn build_ipv6_tcp_syn(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, extra_payload_len: usize) -> Vec<u8> {
        let payload_len = (20 + extra_payload_len) as u16;
        let mut pkt = vec![0u8; 40 + usize::from(payload_len)];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&payload_len.to_be_bytes());
        pkt[6] = 6; // TCP
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&src_ip.octets());
        pkt[24..40].copy_from_slice(&dst_ip.octets());
        pkt[40..42].copy_from_slice(&45001u16.to_be_bytes());
        pkt[42..44].copy_from_slice(&443u16.to_be_bytes());
        pkt[52] = 0x50;
        pkt[53] = 0x02;
        pkt[60..].fill(0xab);
        pkt
    }

    #[test]
    fn quic_udp_443_blocker_exempts_rfc5389_stun_packets() {
        let mut stun_min = [0u8; 20];
        stun_min[0..2].copy_from_slice(&[0x00, 0x01]); // Binding Request
        stun_min[4..8].copy_from_slice(&STUN_MAGIC_COOKIE);
        assert!(!is_blocked_quic_udp(443, &stun_min));

        let mut stun_turn = [0u8; 64];
        stun_turn[0..2].copy_from_slice(&[0x00, 0x03]); // TURN Allocate Request
        stun_turn[4..8].copy_from_slice(&STUN_MAGIC_COOKIE);
        assert!(!is_blocked_quic_udp(443, &stun_turn));

        // Shorter than 20 bytes is not a valid RFC 5389 STUN header and remains blocked.
        let mut short_cookie = [0u8; 12];
        short_cookie[4..8].copy_from_slice(&STUN_MAGIC_COOKIE);
        assert!(is_blocked_quic_udp(443, &short_cookie));

        // Non-STUN UDP/443 payload >= 20 bytes remains blocked.
        let non_stun = [0xc0u8; 20];
        assert!(is_blocked_quic_udp(443, &non_stun));

        // QUIC long header with non-zero leading 2 bits plus STUN magic cookie must remain blocked.
        let mut spoofed_quic = [0xc0u8; 24];
        spoofed_quic[4..8].copy_from_slice(&STUN_MAGIC_COOKIE);
        assert!(!is_stun_packet(&spoofed_quic));
        assert!(is_blocked_quic_udp(443, &spoofed_quic));
    }

    #[test]
    fn icmpv4_port_unreachable_builds_valid_rfc792_packet_and_checksums() {
        // RFC 1071 Section 3 reference vector.
        assert_eq!(
            internet_checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            0x220d
        );

        let orig_src = Ipv4Addr::new(10, 0, 0, 2);
        let orig_dst = Ipv4Addr::new(1, 1, 1, 1);
        let payload = [0xc0u8; 1200];
        let invoking = build_ipv4_udp(orig_src, 51234, orig_dst, 443, &payload);

        let icmp =
            build_icmp_port_unreachable(&invoking).expect("expected IPv4 ICMP Port Unreachable");
        // 20 outer IPv4 + 8 ICMPv4 + (20 invoking IPv4 + 8 UDP + 64 UDP payload) = 120 bytes
        assert_eq!(icmp.len(), 120);
        assert_eq!(icmp[0], 0x45);
        assert_eq!(u16::from_be_bytes([icmp[2], icmp[3]]), 120);
        assert_eq!(icmp[9], IP_PROTO_ICMP);
        assert_eq!(&icmp[12..16], orig_dst.octets().as_slice());
        assert_eq!(&icmp[16..20], orig_src.octets().as_slice());

        // Verify IPv4 header checksum directly and via recomputation.
        assert_eq!(internet_checksum(&icmp[..20]), 0);
        let mut ip_hdr_zeroed = icmp[..20].to_vec();
        ip_hdr_zeroed[10] = 0;
        ip_hdr_zeroed[11] = 0;
        assert_eq!(
            u16::from_be_bytes([icmp[10], icmp[11]]),
            internet_checksum(&ip_hdr_zeroed)
        );

        // Verify ICMPv4 Type 3 Code 3, unused bytes, checksum, and quoted payload.
        assert_eq!(icmp[20], ICMPV4_TYPE_DEST_UNREACHABLE);
        assert_eq!(icmp[21], ICMPV4_CODE_PORT_UNREACHABLE);
        assert_eq!(&icmp[24..28], [0u8; 4].as_slice());
        assert_eq!(internet_checksum(&icmp[20..]), 0);
        let mut icmp_zeroed = icmp[20..].to_vec();
        icmp_zeroed[2] = 0;
        icmp_zeroed[3] = 0;
        assert_eq!(
            u16::from_be_bytes([icmp[22], icmp[23]]),
            internet_checksum(&icmp_zeroed)
        );
        assert_eq!(&icmp[28..], &invoking[..92]);
        assert!(SlicedPacket::from_ip(&icmp).is_ok());
        assert!(is_valid_inbound_tun_packet(&icmp));

        // Verify odd-length small UDP payload keeps full quote and valid checksums.
        let small = build_ipv4_udp(orig_src, 51235, orig_dst, 443, b"odd-13-bytes!");
        let small_icmp =
            build_icmp_port_unreachable(&small).expect("expected odd-length ICMPv4 reply");
        assert_eq!(small_icmp.len(), 20 + 8 + small.len());
        assert_eq!(&small_icmp[28..], small.as_slice());
        assert_eq!(internet_checksum(&small_icmp[..20]), 0);
        assert_eq!(internet_checksum(&small_icmp[20..]), 0);
    }

    #[test]
    fn icmpv4_port_unreachable_rejects_multicast_broadcast_unspecified_and_non_udp() {
        let valid_dst = Ipv4Addr::new(1, 1, 1, 1);
        let valid_src = Ipv4Addr::new(10, 0, 0, 2);

        let mcast_src = build_ipv4_udp(Ipv4Addr::new(224, 0, 0, 1), 40000, valid_dst, 443, b"quic");
        assert!(build_icmp_port_unreachable(&mcast_src).is_none());

        let bcast_src = build_ipv4_udp(Ipv4Addr::BROADCAST, 40000, valid_dst, 443, b"quic");
        assert!(build_icmp_port_unreachable(&bcast_src).is_none());

        let unspec_src = build_ipv4_udp(Ipv4Addr::UNSPECIFIED, 40000, valid_dst, 443, b"quic");
        assert!(build_icmp_port_unreachable(&unspec_src).is_none());

        let mcast_dst = build_ipv4_udp(
            valid_src,
            40000,
            Ipv4Addr::new(224, 0, 0, 251),
            5353,
            b"mdns",
        );
        assert!(build_icmp_port_unreachable(&mcast_dst).is_none());

        let bcast_dst = build_ipv4_udp(valid_src, 40000, Ipv4Addr::BROADCAST, 443, b"bcast");
        assert!(build_icmp_port_unreachable(&bcast_dst).is_none());

        let unspec_dst = build_ipv4_udp(valid_src, 40000, Ipv4Addr::UNSPECIFIED, 443, b"unspec");
        assert!(build_icmp_port_unreachable(&unspec_dst).is_none());

        let tcp_pkt = build_ipv4_tcp_syn(valid_src, valid_dst);
        assert!(build_icmp_port_unreachable(&tcp_pkt).is_none());
    }

    #[test]
    fn icmpv6_port_unreachable_builds_valid_rfc4443_packet_and_truncates_to_min_mtu() {
        let orig_src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let orig_dst = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);

        // Oversized UDP/443 packet (40 + 8 + 1400 = 1448 bytes > 1280 MTU).
        let invoking = build_ipv6_with_ext_headers(
            orig_src,
            orig_dst,
            IP_PROTO_UDP,
            &[],
            54321,
            443,
            &[0xc0u8; 1400],
        );
        let icmp =
            build_icmp_port_unreachable(&invoking).expect("expected IPv6 ICMPv6 Port Unreachable");
        assert_eq!(icmp.len(), IPV6_MIN_MTU);
        assert_eq!(icmp[0] >> 4, 6);
        assert_eq!(
            u16::from_be_bytes([icmp[4], icmp[5]]),
            (IPV6_MIN_MTU - 40) as u16
        );
        assert_eq!(icmp[6], IP_PROTO_ICMPV6);
        assert_eq!(&icmp[8..24], orig_dst.octets().as_slice());
        assert_eq!(&icmp[24..40], orig_src.octets().as_slice());
        assert_eq!(icmp[40], ICMPV6_TYPE_DEST_UNREACHABLE);
        assert_eq!(icmp[41], ICMPV6_CODE_PORT_UNREACHABLE);
        assert_eq!(&icmp[44..48], [0u8; 4].as_slice());
        assert_eq!(&icmp[48..], &invoking[..(IPV6_MIN_MTU - 48)]);

        // Verify ICMPv6 pseudo-header checksum directly and via recomputation.
        assert_eq!(icmpv6_checksum(orig_dst, orig_src, &icmp[40..]), 0);
        let mut icmp_zeroed = icmp[40..].to_vec();
        icmp_zeroed[2] = 0;
        icmp_zeroed[3] = 0;
        assert_eq!(
            u16::from_be_bytes([icmp[42], icmp[43]]),
            icmpv6_checksum(orig_dst, orig_src, &icmp_zeroed)
        );
        assert!(SlicedPacket::from_ip(&icmp).is_ok());
        assert!(is_valid_inbound_tun_packet(&icmp));

        // Odd-length small IPv6 UDP payload preserves entire invoking packet and valid checksum.
        let small = build_ipv6_with_ext_headers(
            orig_src,
            orig_dst,
            IP_PROTO_UDP,
            &[],
            54322,
            443,
            b"odd-15-byte-msg",
        );
        let small_icmp =
            build_icmp_port_unreachable(&small).expect("expected odd-length ICMPv6 reply");
        assert_eq!(small_icmp.len(), 40 + 8 + small.len());
        assert_eq!(&small_icmp[48..], small.as_slice());
        assert_eq!(icmpv6_checksum(orig_dst, orig_src, &small_icmp[40..]), 0);

        // Reject multicast/unspecified addresses and non-UDP IPv6 packets.
        let mcast = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        let mcast_src =
            build_ipv6_with_ext_headers(mcast, orig_dst, IP_PROTO_UDP, &[], 54321, 443, b"quic");
        assert!(build_icmp_port_unreachable(&mcast_src).is_none());

        let unspec_src = build_ipv6_with_ext_headers(
            Ipv6Addr::UNSPECIFIED,
            orig_dst,
            IP_PROTO_UDP,
            &[],
            54321,
            443,
            b"quic",
        );
        assert!(build_icmp_port_unreachable(&unspec_src).is_none());

        let mcast_dst =
            build_ipv6_with_ext_headers(orig_src, mcast, IP_PROTO_UDP, &[], 54321, 443, b"quic");
        assert!(build_icmp_port_unreachable(&mcast_dst).is_none());

        let tcp_v6 = build_ipv6_tcp_syn(orig_src, orig_dst, 0);
        assert!(build_icmp_port_unreachable(&tcp_v6).is_none());
    }

    #[test]
    fn icmpv6_no_route_builds_valid_type1_code0_and_rejects_invalid_packets() {
        let orig_src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
        let orig_dst = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);

        let tcp_syn = build_ipv6_tcp_syn(orig_src, orig_dst, 0);
        let icmp = build_icmpv6_no_route(&tcp_syn).expect("expected ICMPv6 No Route for TCP SYN");
        assert_eq!(icmp.len(), 40 + 8 + tcp_syn.len());
        assert_eq!(icmp[0] >> 4, 6);
        assert_eq!(icmp[6], IP_PROTO_ICMPV6);
        assert_eq!(&icmp[8..24], orig_dst.octets().as_slice());
        assert_eq!(&icmp[24..40], orig_src.octets().as_slice());
        assert_eq!(icmp[40], ICMPV6_TYPE_DEST_UNREACHABLE);
        assert_eq!(icmp[41], ICMPV6_CODE_NO_ROUTE);
        assert_eq!(&icmp[44..48], [0u8; 4].as_slice());
        assert_eq!(&icmp[48..], tcp_syn.as_slice());
        assert_eq!(icmpv6_checksum(orig_dst, orig_src, &icmp[40..]), 0);
        assert!(SlicedPacket::from_ip(&icmp).is_ok());
        assert!(is_valid_inbound_tun_packet(&icmp));

        // Oversized IPv6 packet is truncated to fit the 1280-byte IPv6 minimum MTU.
        let large_v6 = build_ipv6_tcp_syn(orig_src, orig_dst, 1400);
        let large_icmp =
            build_icmpv6_no_route(&large_v6).expect("expected truncated ICMPv6 No Route");
        assert_eq!(large_icmp.len(), IPV6_MIN_MTU);
        assert_eq!(icmpv6_checksum(orig_dst, orig_src, &large_icmp[40..]), 0);

        // Must not generate ICMPv6 error in response to an ICMPv6 error message.
        assert!(build_icmpv6_no_route(&icmp).is_none());

        // Reject IPv4 packets and multicast/unspecified IPv6 addresses.
        let v4_pkt = build_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 2),
            50000,
            Ipv4Addr::new(1, 1, 1, 1),
            443,
            b"v4",
        );
        assert!(build_icmpv6_no_route(&v4_pkt).is_none());

        let mcast = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        assert!(build_icmpv6_no_route(&build_ipv6_tcp_syn(mcast, orig_dst, 0)).is_none());
        assert!(
            build_icmpv6_no_route(&build_ipv6_tcp_syn(Ipv6Addr::UNSPECIFIED, orig_dst, 0))
                .is_none()
        );
        assert!(build_icmpv6_no_route(&build_ipv6_tcp_syn(orig_src, mcast, 0)).is_none());
    }

    #[test]
    fn build_udp_packet_ipv4_and_ipv6_checksums_and_zero_checksum_normalization() {
        let v4_src = Ipv4Addr::new(1, 1, 1, 1);
        let v4_dst = Ipv4Addr::new(10, 0, 0, 2);
        let src_v4 = SocketAddr::new(IpAddr::V4(v4_src), 53);
        let dst_v4 = SocketAddr::new(IpAddr::V4(v4_dst), 53001);

        for payload in [b"even-payload".as_slice(), b"odd-payload-13!".as_slice()] {
            let pkt = build_udp_packet(src_v4, dst_v4, payload).expect("IPv4 UDP packet");
            assert_eq!(pkt.len(), 20 + 8 + payload.len());
            assert_eq!(pkt[0], 0x45);
            assert_eq!(pkt[9], IP_PROTO_UDP);
            assert_eq!(internet_checksum(&pkt[..20]), 0);
            let mut udp_zero = pkt[20..].to_vec();
            udp_zero[6] = 0;
            udp_zero[7] = 0;
            let expected_cksum = udp_ipv4_checksum(v4_src, v4_dst, &udp_zero);
            assert_eq!(u16::from_be_bytes([pkt[26], pkt[27]]), expected_cksum);
            // One's complement verification over pseudo-header + full UDP segment equals 0.
            let mut sum = 0u32;
            sum = internet_checksum_partial(sum, &v4_src.octets());
            sum = internet_checksum_partial(sum, &v4_dst.octets());
            sum = internet_checksum_partial(sum, &[0, IP_PROTO_UDP]);
            sum = internet_checksum_partial(sum, &(pkt[20..].len() as u16).to_be_bytes());
            sum = internet_checksum_partial(sum, &pkt[20..]);
            assert_eq!(finalize_checksum(sum), 0);

            assert!(SlicedPacket::from_ip(&pkt).is_ok());
            let parsed = inspect_inbound_udp(&pkt).expect("inspect IPv4 UDP");
            assert_eq!(parsed.src_ip, IpAddr::V4(v4_src));
            assert_eq!(parsed.dst_ip, IpAddr::V4(v4_dst));
            assert_eq!(parsed.src_port, 53);
            assert_eq!(parsed.dst_port, 53001);
            assert_eq!(parsed.payload, payload);
        }

        let v6_src = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let v6_dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let src_v6 = SocketAddr::new(IpAddr::V6(v6_src), 53);
        let dst_v6 = SocketAddr::new(IpAddr::V6(v6_dst), 53002);

        for payload in [b"ipv6-even!".as_slice(), b"ipv6-odd-payload!".as_slice()] {
            let pkt = build_udp_packet(src_v6, dst_v6, payload).expect("IPv6 UDP packet");
            assert_eq!(pkt.len(), 40 + 8 + payload.len());
            assert_eq!(pkt[0] >> 4, 6);
            assert_eq!(pkt[6], IP_PROTO_UDP);
            let stored_cksum = u16::from_be_bytes([pkt[46], pkt[47]]);
            assert_ne!(stored_cksum, 0);
            let mut udp_zero = pkt[40..].to_vec();
            udp_zero[6] = 0;
            udp_zero[7] = 0;
            assert_eq!(stored_cksum, udp_ipv6_checksum(v6_src, v6_dst, &udp_zero));
            let mut sum = 0u32;
            sum = internet_checksum_partial(sum, &v6_src.octets());
            sum = internet_checksum_partial(sum, &v6_dst.octets());
            sum = internet_checksum_partial(sum, &(pkt[40..].len() as u32).to_be_bytes());
            sum = internet_checksum_partial(sum, &[0, 0, 0, IP_PROTO_UDP]);
            sum = internet_checksum_partial(sum, &pkt[40..]);
            assert_eq!(finalize_checksum(sum), 0);

            assert!(SlicedPacket::from_ip(&pkt).is_ok());
            let parsed = inspect_inbound_udp(&pkt).expect("inspect IPv6 UDP");
            assert_eq!(parsed.src_ip, IpAddr::V6(v6_src));
            assert_eq!(parsed.dst_ip, IpAddr::V6(v6_dst));
            assert_eq!(parsed.src_port, 53);
            assert_eq!(parsed.dst_port, 53002);
            assert_eq!(parsed.payload, payload);
        }

        // Craft a 2-byte payload whose computed RFC 8200 UDP checksum is 0x0000;
        // build_udp_packet must encode it as non-zero 0xFFFF.
        let probe_v6 = build_udp_packet(src_v6, dst_v6, &[0u8, 0u8]).unwrap();
        let mut probe_zero = probe_v6[40..].to_vec();
        probe_zero[6] = 0;
        probe_zero[7] = 0;
        let raw_zero_payload = {
            let mut sum = 0u32;
            sum = internet_checksum_partial(sum, &v6_src.octets());
            sum = internet_checksum_partial(sum, &v6_dst.octets());
            sum = internet_checksum_partial(sum, &(probe_zero.len() as u32).to_be_bytes());
            sum = internet_checksum_partial(sum, &[0, 0, 0, IP_PROTO_UDP]);
            sum = internet_checksum_partial(sum, &probe_zero);
            finalize_checksum(sum)
        };
        let zero_cksum_v6 =
            build_udp_packet(src_v6, dst_v6, &raw_zero_payload.to_be_bytes()).unwrap();
        assert_eq!(
            u16::from_be_bytes([zero_cksum_v6[46], zero_cksum_v6[47]]),
            0xffff
        );
        let mut verify_sum = 0u32;
        verify_sum = internet_checksum_partial(verify_sum, &v6_src.octets());
        verify_sum = internet_checksum_partial(verify_sum, &v6_dst.octets());
        verify_sum = internet_checksum_partial(
            verify_sum,
            &(zero_cksum_v6[40..].len() as u32).to_be_bytes(),
        );
        verify_sum = internet_checksum_partial(verify_sum, &[0, 0, 0, IP_PROTO_UDP]);
        verify_sum = internet_checksum_partial(verify_sum, &zero_cksum_v6[40..]);
        assert_eq!(finalize_checksum(verify_sum), 0);

        // Mismatched IP families must be rejected.
        assert!(build_udp_packet(src_v4, dst_v6, b"mismatch").is_none());
        assert!(build_udp_packet(src_v6, dst_v4, b"mismatch").is_none());
    }

    #[test]
    fn build_truncated_dns_reply_strips_edns0_opt_and_preserves_question() {
        let base_query = encode_dns_query("example.com", 1).unwrap();
        let mut edns_query = base_query.clone();
        // Set ARCOUNT = 1 and append an 11-byte EDNS0 OPT pseudo-record.
        edns_query[10] = 0;
        edns_query[11] = 1;
        edns_query.extend_from_slice(&[
            0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);

        let mut full_resp = base_query.clone();
        full_resp[2] = 0x81;
        full_resp[3] = 0x80;
        full_resp[7] = 5;

        let truncated = build_truncated_dns_reply(&edns_query, &full_resp);
        assert_ne!(truncated[2] & 0x02, 0, "TC bit must be set");
        assert_eq!(u16::from_be_bytes([truncated[4], truncated[5]]), 1);
        assert_eq!(&truncated[6..12], &[0u8; 6]);
        assert_eq!(
            truncated.len(),
            base_query.len(),
            "EDNS0 OPT bytes must be stripped from truncated DNS reply"
        );
        assert_eq!(&truncated[12..], &base_query[12..]);

        // Malformed query falls back cleanly to a 12-byte TC=1 header with QDCOUNT=0.
        let mut bad_query = vec![0u8; 16];
        bad_query[5] = 1;
        bad_query[12] = 40; // label length exceeds remaining bytes
        let fallback = build_truncated_dns_reply(&bad_query, &full_resp);
        assert_eq!(fallback.len(), 12);
        assert_eq!(u16::from_be_bytes([fallback[4], fallback[5]]), 0);
        assert_ne!(fallback[2] & 0x02, 0);
    }

    #[test]
    fn ipv6_hop_by_hop_only_at_offset_40_and_exact_max_ext_headers_icmpv6() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        // Destination Options (offset 40) -> Hop-by-Hop (offset 48) -> UDP must be rejected.
        let mut bad_hbh = Vec::new();
        bad_hbh.extend_from_slice(&[IPV6_NEXT_HOP_BY_HOP, 0, 1, 4, 0, 0, 0, 0]);
        bad_hbh.extend_from_slice(&[IP_PROTO_UDP, 0, 1, 4, 0, 0, 0, 0]);
        let bad_hbh_pkt = build_ipv6_with_ext_headers(
            src,
            dst,
            IPV6_NEXT_DEST_OPTS,
            &bad_hbh,
            50000,
            53,
            b"bad-hbh",
        );
        assert!(inspect_inbound_udp(&bad_hbh_pkt).is_none());

        // Exactly MAX_IPV6_EXT_HEADERS (8) extension headers followed by TCP must NOT be
        // misclassified as an ICMPv6 error by `is_icmpv6_error_or_non_initial_fragment`.
        let mut ext8 = Vec::new();
        for idx in 0..MAX_IPV6_EXT_HEADERS {
            let next = if idx + 1 == MAX_IPV6_EXT_HEADERS {
                6 // TCP
            } else {
                IPV6_NEXT_DEST_OPTS
            };
            ext8.extend_from_slice(&[next, 0, 1, 4, 0, 0, 0, 0]);
        }
        let payload_len = (ext8.len() + 20) as u16;
        let mut pkt8 = Vec::with_capacity(40 + usize::from(payload_len));
        pkt8.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        pkt8.extend_from_slice(&payload_len.to_be_bytes());
        pkt8.push(IPV6_NEXT_HOP_BY_HOP);
        pkt8.push(64);
        pkt8.extend_from_slice(&src.octets());
        pkt8.extend_from_slice(&dst.octets());
        pkt8.extend_from_slice(&ext8);
        pkt8.extend_from_slice(&[0u8; 20]);
        assert!(
            build_icmpv6_no_route(&pkt8).is_some(),
            "8 valid ext headers + TCP must produce ICMPv6 No Route"
        );

        // 8 extension headers followed by ICMPv6 error (type 1) must still be suppressed.
        let mut ext8_icmp = Vec::new();
        for idx in 0..MAX_IPV6_EXT_HEADERS {
            let next = if idx + 1 == MAX_IPV6_EXT_HEADERS {
                IP_PROTO_ICMPV6
            } else {
                IPV6_NEXT_DEST_OPTS
            };
            ext8_icmp.extend_from_slice(&[next, 0, 1, 4, 0, 0, 0, 0]);
        }
        let icmp_payload_len = (ext8_icmp.len() + 8) as u16;
        let mut pkt8_icmp = Vec::with_capacity(40 + usize::from(icmp_payload_len));
        pkt8_icmp.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        pkt8_icmp.extend_from_slice(&icmp_payload_len.to_be_bytes());
        pkt8_icmp.push(IPV6_NEXT_HOP_BY_HOP);
        pkt8_icmp.push(64);
        pkt8_icmp.extend_from_slice(&src.octets());
        pkt8_icmp.extend_from_slice(&dst.octets());
        pkt8_icmp.extend_from_slice(&ext8_icmp);
        pkt8_icmp.extend_from_slice(&[ICMPV6_TYPE_DEST_UNREACHABLE, 0, 0, 0, 0, 0, 0, 0]);
        assert!(build_icmpv6_no_route(&pkt8_icmp).is_none());
    }

    #[test]
    fn max_udp_payload_caps_dns_at_1232_and_build_udp_handles_65507() {
        assert_eq!(max_dns_udp_payload_for_mtu(16384, true), 1232);
        assert_eq!(max_dns_udp_payload_for_mtu(16384, false), 1232);
        assert_eq!(max_dns_udp_payload_for_mtu(65535, true), 1232);
        assert_eq!(max_dns_udp_payload_for_mtu(65535, false), 1232);
        assert_eq!(max_dns_udp_payload_for_mtu(1280, false), 1232);
        assert_eq!(max_dns_udp_payload_for_mtu(1000, true), 972);

        assert_eq!(max_udp_payload_for_mtu(16384, true), 16384 - 28);
        assert_eq!(max_udp_payload_for_mtu(16384, false), 16384 - 48);
        assert_eq!(max_udp_payload_for_mtu(65535, true), 65507);
        assert_eq!(max_udp_payload_for_mtu(65535, false), 65535 - 48);

        let mut max_payload = vec![0xffu8; 65507];

        let v4_src = Ipv4Addr::new(1, 1, 1, 1);
        let v4_dst = Ipv4Addr::new(198, 18, 0, 1);
        let src_v4 = SocketAddr::new(IpAddr::V4(v4_src), 443);
        let dst_v4 = SocketAddr::new(IpAddr::V4(v4_dst), 51000);
        let pkt_v4 = build_udp_packet(src_v4, dst_v4, &max_payload).expect("max IPv4 UDP packet");
        assert_eq!(pkt_v4.len(), 65535);
        assert_eq!(internet_checksum(&pkt_v4[..20]), 0);
        let parsed_v4 = inspect_inbound_udp(&pkt_v4).expect("inspect max IPv4 UDP");
        assert_eq!(parsed_v4.payload.len(), 65507);

        let v6_src = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let v6_dst = Ipv6Addr::new(0xfd00, 0x7664, 0x7069, 0, 0, 0, 0, 1);
        let src_v6 = SocketAddr::new(IpAddr::V6(v6_src), 443);
        let dst_v6 = SocketAddr::new(IpAddr::V6(v6_dst), 51001);
        let pkt_v6 = build_udp_packet(src_v6, dst_v6, &max_payload).expect("max IPv6 UDP packet");
        assert_eq!(pkt_v6.len(), 40 + 8 + 65507);
        let parsed_v6 = inspect_inbound_udp(&pkt_v6).expect("inspect max IPv6 UDP");
        assert_eq!(parsed_v6.payload.len(), 65507);

        max_payload.push(0);
        assert!(build_udp_packet(src_v4, dst_v4, &max_payload).is_none());
    }
}
