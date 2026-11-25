/// Zero-panic TLS ClientHello parser, SNI extractor, and RFC-compliant TLS record splitter.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// Lowercased Server Name Indication hostname, if present.
    pub sni: Option<String>,
    /// Total length of the outer TLS record (`5 + record_payload_len`).
    pub record_total_len: usize,
    /// Byte offset of the SNI hostname relative to the TLS record payload (`buf[5..]`).
    pub sni_payload_offset: Option<usize>,
    /// Byte length of the SNI hostname.
    pub sni_len: Option<usize>,
}

/// Checks if the initial bytes look like a TLS Handshake record (`0x16 0x03 0x00..=0x04`).
/// Returns `Some(5 + record_len)` when the 5-byte TLS record header is valid and within RFC bounds.
pub fn expected_tls_record_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 5 {
        return None;
    }
    if buf[0] != 0x16 || buf[1] != 0x03 || buf[2] > 0x04 {
        return None;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if rec_len == 0 || rec_len > 16384 {
        return None;
    }
    Some(5 + rec_len)
}

/// Parses a complete initial TLS ClientHello record and extracts SNI metadata if present.
pub fn parse_client_hello(buf: &[u8]) -> Option<ClientHelloInfo> {
    let total_len = expected_tls_record_len(buf)?;
    if buf.len() < total_len {
        return None;
    }

    let payload = &buf[5..total_len];
    // Handshake header: msg_type (1) == 0x01 (ClientHello), length (3)
    if payload.len() < 4 || payload[0] != 0x01 {
        return None;
    }
    let hs_len =
        ((payload[1] as usize) << 16) | ((payload[2] as usize) << 8) | (payload[3] as usize);
    let hs_end = (4 + hs_len).min(payload.len());

    // ClientVersion (2) + Random (32)
    let mut pos = 4 + 2 + 32;
    if pos >= hs_end {
        return Some(ClientHelloInfo {
            sni: None,
            record_total_len: total_len,
            sni_payload_offset: None,
            sni_len: None,
        });
    }

    // Session ID
    let session_id_len = payload[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > hs_end {
        return Some(ClientHelloInfo {
            sni: None,
            record_total_len: total_len,
            sni_payload_offset: None,
            sni_len: None,
        });
    }

    // Cipher Suites
    let cipher_suites_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    if pos + 1 > hs_end {
        return Some(ClientHelloInfo {
            sni: None,
            record_total_len: total_len,
            sni_payload_offset: None,
            sni_len: None,
        });
    }

    // Compression Methods
    let comp_methods_len = payload[pos] as usize;
    pos += 1 + comp_methods_len;
    if pos + 2 > hs_end {
        return Some(ClientHelloInfo {
            sni: None,
            record_total_len: total_len,
            sni_payload_offset: None,
            sni_len: None,
        });
    }

    // Extensions
    let ext_total_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total_len).min(hs_end);

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            break;
        }

        if ext_type == 0x0000 && ext_len >= 5 {
            let sni_list_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
            let list_end = (pos + 2 + sni_list_len).min(pos + ext_len);
            let mut sni_pos = pos + 2;
            while sni_pos + 3 <= list_end {
                let name_type = payload[sni_pos];
                let name_len =
                    u16::from_be_bytes([payload[sni_pos + 1], payload[sni_pos + 2]]) as usize;
                sni_pos += 3;
                if sni_pos + name_len > list_end {
                    break;
                }
                if name_type == 0x00 && name_len > 0 {
                    if let Ok(raw_host) = std::str::from_utf8(&payload[sni_pos..sni_pos + name_len])
                    {
                        return Some(ClientHelloInfo {
                            sni: Some(raw_host.to_ascii_lowercase()),
                            record_total_len: total_len,
                            sni_payload_offset: Some(sni_pos),
                            sni_len: Some(name_len),
                        });
                    }
                }
                sni_pos += name_len;
            }
        }

        pos += ext_len;
    }

    Some(ClientHelloInfo {
        sni: None,
        record_total_len: total_len,
        sni_payload_offset: None,
        sni_len: None,
    })
}

/// Splits a TLS ClientHello into two valid TLS Handshake (`0x16`) records right at the middle
/// of the SNI hostname (or at `fallback_split` if no SNI is present).
/// Preserves any coalesced trailing bytes after the first TLS record in the second part.
pub fn split_tls_records(
    buf: &[u8],
    info: &ClientHelloInfo,
    fallback_split: usize,
) -> Option<(Vec<u8>, Vec<u8>)> {
    if buf.len() < info.record_total_len || info.record_total_len <= 6 {
        return None;
    }

    let payload = &buf[5..info.record_total_len];
    let split_pos = match (info.sni_payload_offset, info.sni_len) {
        (Some(off), Some(len)) if len >= 2 => off + (len / 2),
        (Some(off), Some(_)) => off,
        _ => fallback_split,
    }
    .clamp(1, payload.len() - 1);

    let (p1, p2) = payload.split_at(split_pos);
    let trailing = &buf[info.record_total_len..];

    let mut rec1 = Vec::with_capacity(5 + p1.len());
    rec1.extend_from_slice(&[
        buf[0],
        buf[1],
        buf[2],
        ((p1.len() >> 8) & 0xff) as u8,
        (p1.len() & 0xff) as u8,
    ]);
    rec1.extend_from_slice(p1);

    let mut rec2 = Vec::with_capacity(5 + p2.len() + trailing.len());
    rec2.extend_from_slice(&[
        buf[0],
        buf[1],
        buf[2],
        ((p2.len() >> 8) & 0xff) as u8,
        (p2.len() & 0xff) as u8,
    ]);
    rec2.extend_from_slice(p2);
    rec2.extend_from_slice(trailing);

    Some((rec1, rec2))
}

fn compute_multi_record_splits_with_fallback(
    payload: &[u8],
    info: &ClientHelloInfo,
    fallback_split: usize,
) -> Option<([usize; 4], usize)> {
    if payload.len() < info.record_total_len || info.record_total_len <= 8 {
        return None;
    }

    let rec_payload_len = info.record_total_len - 5;
    let max_cut = rec_payload_len - 1;
    let mut raw = [0usize; 3];
    let mut raw_len = 0usize;

    if max_cut >= 2 {
        raw[raw_len] = 2;
        raw_len += 1;
    }

    match (info.sni_payload_offset, info.sni_len) {
        (Some(off), Some(len)) if len >= 3 => {
            raw[raw_len] = off.saturating_add(1).clamp(1, max_cut);
            raw_len += 1;
            raw[raw_len] = off.saturating_add((len / 2).max(2)).clamp(1, max_cut);
            raw_len += 1;
        }
        (Some(off), Some(len)) if len > 0 => {
            raw[raw_len] = off.saturating_add((len / 2).max(1)).clamp(1, max_cut);
            raw_len += 1;
        }
        _ => {
            raw[raw_len] = fallback_split.clamp(1, max_cut);
            raw_len += 1;
        }
    }

    raw[..raw_len].sort_unstable();

    let mut bounds = [0usize; 4];
    let mut count = 0usize;
    let mut prev = 0usize;
    for &cut in &raw[..raw_len] {
        if cut > prev && cut < rec_payload_len {
            bounds[count] = cut;
            count += 1;
            prev = cut;
        }
    }

    if count == 0 {
        return None;
    }

    bounds[count] = rec_payload_len;
    count += 1;

    Some((bounds, count))
}

/// Computes 2–4 RFC-compliant TLS Handshake record split end boundaries on the stack
/// without heap allocation.
///
/// `payload` must contain the full initial TLS record starting with its 5-byte header
/// (`payload.len() >= info.record_total_len`). On success, returns `(bounds, count)`
/// where `bounds[..count]` (`2 <= count <= 4`) are strictly ascending end offsets into
/// the TLS record payload (`&payload[5..info.record_total_len]`), ending with
/// `info.record_total_len - 5`.
pub fn compute_multi_record_splits(
    payload: &[u8],
    info: &ClientHelloInfo,
) -> Option<([usize; 4], usize)> {
    let fallback_split = (info.record_total_len.saturating_sub(5) / 2).max(1);
    compute_multi_record_splits_with_fallback(payload, info, fallback_split)
}

/// Splits a TLS ClientHello into 3–4 RFC-compliant TLS Handshake (`0x16`) records:
/// - Record 1: first 2 bytes of the handshake header (`[0x01, len_hi]`)
/// - Record 2: up to the 1st byte of the SNI hostname
/// - Record 3: slice through the midpoint of the SNI hostname
/// - Record 4: remainder of the ClientHello (plus any coalesced trailing bytes)
///
/// Defeats both single-packet SNI filters and active inline DPI boxes that attempt
/// shallow 2-record TLS reassembly.
pub fn split_tls_records_multi(
    buf: &[u8],
    info: &ClientHelloInfo,
    fallback_split: usize,
) -> Option<Vec<Vec<u8>>> {
    let (bounds, count) = compute_multi_record_splits_with_fallback(buf, info, fallback_split)?;
    let payload = &buf[5..info.record_total_len];
    let trailing = &buf[info.record_total_len..];
    let mut records = Vec::with_capacity(count);
    let mut prev = 0usize;

    for &cut in &bounds[..count] {
        let slice = &payload[prev..cut];
        let is_last = cut == payload.len();
        let mut rec =
            Vec::with_capacity(5 + slice.len() + if is_last { trailing.len() } else { 0 });
        rec.extend_from_slice(&[
            buf[0],
            buf[1],
            buf[2],
            ((slice.len() >> 8) & 0xff) as u8,
            (slice.len() & 0xff) as u8,
        ]);
        rec.extend_from_slice(slice);
        if is_last && !trailing.is_empty() {
            rec.extend_from_slice(trailing);
        }
        records.push(rec);
        prev = cut;
    }

    if records.len() < 2 {
        return None;
    }
    Some(records)
}

/// Splits a TLS ClientHello into a deep sequence of 12+ RFC-compliant TLS Handshake (`0x16`)
/// records: up to 10 tiny 2-byte lead records before the SNI extension (exhausting hardware
/// DPI per-flow packet-inspection caps before the hostname even hits the wire) followed by
/// SNI-split records.
pub fn split_tls_records_deep(
    buf: &[u8],
    info: &ClientHelloInfo,
    fallback_split: usize,
) -> Option<Vec<Vec<u8>>> {
    if buf.len() < info.record_total_len || info.record_total_len <= 16 {
        return None;
    }

    let payload = &buf[5..info.record_total_len];
    let max_cut = payload.len() - 1;
    let mut cuts = Vec::with_capacity(16);

    // Emit up to 10 tiny 2-byte TLS handshake records at the very start of ClientHello
    // (ClientHello header + Version + Random) so packet-budget-limited inline DPI boxes
    // stop inspecting the flow before any SNI bytes arrive.
    let lead_limit = info
        .sni_payload_offset
        .unwrap_or(fallback_split.max(24))
        .min(20)
        .min(max_cut);
    let mut pos = 2usize;
    while pos <= lead_limit {
        cuts.push(pos);
        pos += 2;
    }

    // Then slice right through the SNI hostname itself across multiple records.
    match (info.sni_payload_offset, info.sni_len) {
        (Some(off), Some(len)) if len >= 4 => {
            cuts.push((off + 1).clamp(1, max_cut));
            cuts.push((off + (len / 3).max(2)).clamp(1, max_cut));
            cuts.push((off + (len * 2 / 3).max(3)).clamp(1, max_cut));
        }
        (Some(off), Some(len)) if len >= 1 => {
            cuts.push((off + 1).clamp(1, max_cut));
        }
        _ => {
            cuts.push(fallback_split.clamp(1, max_cut));
        }
    }

    cuts.sort_unstable();
    cuts.dedup();

    let trailing = &buf[info.record_total_len..];
    let mut records = Vec::with_capacity(cuts.len() + 1);
    let mut prev = 0usize;

    for cut in cuts.into_iter().chain(std::iter::once(payload.len())) {
        if cut <= prev {
            continue;
        }
        let slice = &payload[prev..cut];
        let is_last = cut == payload.len();
        let mut rec =
            Vec::with_capacity(5 + slice.len() + if is_last { trailing.len() } else { 0 });
        rec.extend_from_slice(&[
            buf[0],
            buf[1],
            buf[2],
            ((slice.len() >> 8) & 0xff) as u8,
            (slice.len() & 0xff) as u8,
        ]);
        rec.extend_from_slice(slice);
        if is_last && !trailing.is_empty() {
            rec.extend_from_slice(trailing);
        }
        records.push(rec);
        prev = cut;
    }

    if records.len() < 3 {
        return None;
    }
    Some(records)
}

/// Extracts the `Host` header hostname, a split inside the `Host:` header name,
/// and the byte offset of the hostname midpoint in a plain HTTP request.
pub fn extract_http_host_splits(buf: &[u8]) -> Option<(String, usize, usize)> {
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(buf.len().min(4096));
    let head = std::str::from_utf8(&buf[..header_end]).ok()?;

    let mut offset = 0usize;
    for line in head.split("\r\n") {
        if line.len() >= 5 && line.as_bytes()[..5].eq_ignore_ascii_case(b"host:") {
            let after_colon = &line[5..];
            let ws = after_colon.len() - after_colon.trim_start().len();
            let trimmed = after_colon.trim();
            let host_only = trimmed
                .split(':')
                .next()
                .unwrap_or(trimmed)
                .trim()
                .to_ascii_lowercase();
            if !host_only.is_empty() {
                let header_split = (offset + 2).clamp(1, buf.len().saturating_sub(1));
                let host_start = offset + 5 + ws;
                let value_split = (host_start + (host_only.len() / 2).max(1))
                    .clamp(header_split, buf.len().saturating_sub(1));
                return Some((host_only, header_split, value_split));
            }
        }
        offset += line.len() + 2;
    }
    None
}

/// Extracts the `Host` header hostname and the byte offset of its midpoint in a plain HTTP request.
pub fn extract_http_host_split(buf: &[u8]) -> Option<(String, usize)> {
    extract_http_host_splits(buf).map(|(host, _, mid)| (host, mid))
}

/// RFC 5389 / RFC 8489 STUN fixed magic cookie (`0x2112A442`) at bytes `4..8`.
const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

/// Detects whether a UDP datagram is an RFC 5389 / RFC 8489 STUN packet.
///
/// Valid STUN headers are at least 20 bytes long, clear the two most significant bits
/// of byte 0 (`payload[0] & 0xc0 == 0x00`), and carry the magic cookie `0x2112A442`
/// at bytes `4..8`.
pub fn is_stun_packet(payload: &[u8]) -> bool {
    payload.len() >= 20 && (payload[0] & 0xc0) == 0x00 && payload[4..8] == STUN_MAGIC_COOKIE
}

/// Detects whether a UDP datagram carries a QUIC Long Header Initial packet
/// (RFC 9000 v1, RFC 9369 v2, IETF draft versions, or RFC 9000 greased versions,
/// including RFC 9287 greased fixed-bit packets).
///
/// Rejects RFC 5389 STUN packets, QUIC Short-Header 1-RTT packets, Version Negotiation,
/// and non-Initial Long-Header packet types (0-RTT, Handshake, Retry).
pub fn is_quic_long_header_initial(payload: &[u8]) -> bool {
    if payload.len() < 7 || is_stun_packet(payload) {
        return false;
    }

    let first = payload[0];
    // Header Form bit (0x80) must be set; Fixed Bit (0x40) may be cleared under RFC 9287.
    if (first & 0x80) == 0 {
        return false;
    }

    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let packet_type = (first & 0x30) >> 4;
    let is_initial_type = match version {
        // QUIC v2 (RFC 9369): Initial packet type is 0b01.
        0x6b33_43cf => packet_type == 0x01,
        // QUIC v1 (RFC 9000) and IETF QUIC drafts: Initial packet type is 0b00.
        0x0000_0001 | 0xff00_0001..=0xff00_00ff => packet_type == 0x00,
        // RFC 9000 greased versions (0x?a?a?a?a): Initial packet type is 0b00.
        v if (v & 0x0f0f_0f0f) == 0x0a0a_0a0a => packet_type == 0x00,
        _ => false,
    };
    if !is_initial_type {
        return false;
    }

    let dcid_len = payload[5] as usize;
    if dcid_len > 20 {
        return false;
    }
    let scid_len_pos = 6 + dcid_len;
    if scid_len_pos >= payload.len() {
        return false;
    }
    let scid_len = payload[scid_len_pos] as usize;
    scid_len <= 20 && scid_len_pos + 1 + scid_len <= payload.len()
}

/// Helper used in tests and diagnostics to craft a standards-compliant TLS 1.3/1.2 ClientHello
/// with an SNI extension and optional padding (e.g. simulating large Post-Quantum ML-KEM key shares).
pub fn build_synthetic_client_hello(sni: &str, extra_padding_len: usize) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();
    // SNI extension (0x0000)
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&0x0000u16.to_be_bytes());
    let list_len = (3 + sni_bytes.len()) as u16;
    sni_ext.extend_from_slice(&(2 + list_len).to_be_bytes());
    sni_ext.extend_from_slice(&list_len.to_be_bytes());
    sni_ext.push(0x00); // host_name
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);

    let mut extensions = sni_ext;
    if extra_padding_len > 0 {
        extensions.extend_from_slice(&0x0015u16.to_be_bytes()); // TLS padding extension
        extensions.extend_from_slice(&(extra_padding_len as u16).to_be_bytes());
        extensions.resize(extensions.len() + extra_padding_len, 0u8);
    }

    let mut ch_body = Vec::new();
    ch_body.extend_from_slice(&[0x03, 0x03]); // Legacy TLS 1.2 version
    ch_body.extend_from_slice(&[0x42; 32]); // Random
    ch_body.push(32); // Session ID len
    ch_body.extend_from_slice(&[0xaa; 32]); // Session ID
    ch_body.extend_from_slice(&4u16.to_be_bytes()); // Cipher suites len
    ch_body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]); // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
    ch_body.push(1); // Compression methods len
    ch_body.push(0x00); // null compression
    ch_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    ch_body.extend_from_slice(&extensions);

    let mut hs = Vec::with_capacity(4 + ch_body.len());
    hs.push(0x01); // ClientHello
    let hs_len = ch_body.len();
    hs.push(((hs_len >> 16) & 0xff) as u8);
    hs.push(((hs_len >> 8) & 0xff) as u8);
    hs.push((hs_len & 0xff) as u8);
    hs.extend_from_slice(&ch_body);

    let mut record = Vec::with_capacity(5 + hs.len());
    record.extend_from_slice(&[
        0x16,
        0x03,
        0x01,
        ((hs.len() >> 8) & 0xff) as u8,
        (hs.len() & 0xff) as u8,
    ]);
    record.extend_from_slice(&hs);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sni_and_splits_post_quantum_sized_client_hello() {
        let ch = build_synthetic_client_hello("updates.discord.com", 1500);
        assert!(ch.len() > 1600);

        let info = parse_client_hello(&ch).expect("valid ClientHello");
        assert_eq!(info.sni.as_deref(), Some("updates.discord.com"));
        assert_eq!(info.record_total_len, ch.len());

        let (rec1, rec2) = split_tls_records(&ch, &info, 10).expect("should split records");
        // Verify neither individual record contains the full plaintext SNI
        let needle = b"updates.discord.com";
        assert!(!rec1.windows(needle.len()).any(|w| w == needle));
        assert!(!rec2.windows(needle.len()).any(|w| w == needle));

        // Verify reassembling the two TLS record payloads reproduces the exact original handshake bytes
        let r1_len = u16::from_be_bytes([rec1[3], rec1[4]]) as usize;
        let r2_len = u16::from_be_bytes([rec2[3], rec2[4]]) as usize;
        assert_eq!(rec1.len(), 5 + r1_len);
        assert_eq!(rec2.len(), 5 + r2_len);

        let mut reassembled = Vec::new();
        reassembled.extend_from_slice(&rec1[5..]);
        reassembled.extend_from_slice(&rec2[5..]);
        assert_eq!(reassembled, ch[5..]);

        let multi = split_tls_records_multi(&ch, &info, 10).expect("should multi-split records");
        assert_eq!(multi.len(), 4);
        assert_eq!(multi[0].len(), 5 + 2);
        let mut multi_reassembled = Vec::new();
        for rec in &multi {
            assert_eq!(rec[0], 0x16);
            assert!(!rec.windows(needle.len()).any(|w| w == needle));
            let rlen = u16::from_be_bytes([rec[3], rec[4]]) as usize;
            assert_eq!(rec.len(), 5 + rlen);
            multi_reassembled.extend_from_slice(&rec[5..]);
        }
        assert_eq!(multi_reassembled, ch[5..]);

        let deep = split_tls_records_deep(&ch, &info, 10).expect("should deep-split records");
        assert!(deep.len() >= 12);
        let mut deep_reassembled = Vec::new();
        for rec in &deep {
            assert_eq!(rec[0], 0x16);
            assert!(!rec.windows(needle.len()).any(|w| w == needle));
            let rlen = u16::from_be_bytes([rec[3], rec[4]]) as usize;
            assert_eq!(rec.len(), 5 + rlen);
            deep_reassembled.extend_from_slice(&rec[5..]);
        }
        assert_eq!(deep_reassembled, ch[5..]);
    }

    #[test]
    fn extracts_http_host_midpoint() {
        let req = b"GET / HTTP/1.1\r\nHost: www.roblox.com\r\nUser-Agent: test\r\n\r\n";
        let (host, split_at) = extract_http_host_split(req).expect("should find Host");
        assert_eq!(host, "www.roblox.com");
        assert!(!req[..split_at].windows(14).any(|w| w == b"www.roblox.com"));
        assert!(!req[split_at..].windows(14).any(|w| w == b"www.roblox.com"));
    }

    #[test]
    fn safely_rejects_malformed_or_non_tls_bytes() {
        assert!(parse_client_hello(b"CONNECT discord.com:443 HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_client_hello(&[0x16, 0x03, 0x01, 0x00, 0x20, 0x01]).is_none());
        assert!(parse_client_hello(&[]).is_none());
    }

    #[test]
    fn computes_stack_multi_record_splits_matching_allocated_splitter() {
        let ch = build_synthetic_client_hello("updates.discord.com", 1500);
        let info = parse_client_hello(&ch).expect("valid ClientHello");

        let (bounds, count) =
            compute_multi_record_splits(&ch, &info).expect("should compute stack splits");
        assert_eq!(count, 4);
        assert_eq!(bounds[0], 2);
        assert_eq!(bounds[count - 1], ch.len() - 5);
        for pair in bounds[..count].windows(2) {
            assert!(pair[0] < pair[1]);
        }

        let multi = split_tls_records_multi(&ch, &info, 10).expect("should multi-split records");
        assert_eq!(multi.len(), count);

        let rec_payload = &ch[5..info.record_total_len];
        let needle = b"updates.discord.com";
        let mut reassembled = Vec::with_capacity(rec_payload.len());
        let mut prev = 0usize;
        for (idx, &cut) in bounds[..count].iter().enumerate() {
            let slice = &rec_payload[prev..cut];
            assert!(!slice.windows(needle.len()).any(|w| w == needle));
            assert_eq!(slice, &multi[idx][5..]);
            reassembled.extend_from_slice(slice);
            prev = cut;
        }
        assert_eq!(reassembled, rec_payload);

        let no_sni_info = ClientHelloInfo {
            sni: None,
            record_total_len: ch.len(),
            sni_payload_offset: None,
            sni_len: None,
        };
        let (no_sni_bounds, no_sni_count) =
            compute_multi_record_splits(&ch, &no_sni_info).expect("should split without SNI");
        assert_eq!(no_sni_count, 3);
        assert_eq!(no_sni_bounds[0], 2);
        assert_eq!(no_sni_bounds[no_sni_count - 1], ch.len() - 5);

        assert!(compute_multi_record_splits(&ch[..8], &info).is_none());
        let tiny_info = ClientHelloInfo {
            sni: None,
            record_total_len: 8,
            sni_payload_offset: None,
            sni_len: None,
        };
        assert!(compute_multi_record_splits(&[0x16; 8], &tiny_info).is_none());
    }

    fn build_quic_long_header(
        first_byte: u8,
        version: u32,
        dcid: &[u8],
        scid: &[u8],
        body_len: usize,
    ) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(7 + dcid.len() + scid.len() + body_len);
        pkt.push(first_byte);
        pkt.extend_from_slice(&version.to_be_bytes());
        pkt.push(dcid.len() as u8);
        pkt.extend_from_slice(dcid);
        pkt.push(scid.len() as u8);
        pkt.extend_from_slice(scid);
        pkt.resize(pkt.len() + body_len, 0u8);
        pkt
    }

    #[test]
    fn detects_quic_long_header_initial_and_rejects_other_packets() {
        let dcid = [0x11; 8];
        let scid = [0x22; 4];

        // QUIC v1 Initial (standard + RFC 9287 greased fixed bit)
        let v1_initial = build_quic_long_header(0xc0, 0x0000_0001, &dcid, &[], 1200);
        let v1_greased = build_quic_long_header(0x80, 0x0000_0001, &dcid, &scid, 64);
        assert!(is_quic_long_header_initial(&v1_initial));
        assert!(is_quic_long_header_initial(&v1_greased));

        // QUIC v2 Initial (RFC 9369: packet type 0b01 -> 0xd0 standard / 0x90 greased)
        let v2_initial = build_quic_long_header(0xd0, 0x6b33_43cf, &dcid, &scid, 1200);
        let v2_greased = build_quic_long_header(0x90, 0x6b33_43cf, &dcid, &[], 64);
        assert!(is_quic_long_header_initial(&v2_initial));
        assert!(is_quic_long_header_initial(&v2_greased));

        // QUIC IETF draft-29 and greased version Initial packets
        let draft_initial = build_quic_long_header(0xc0, 0xff00_001d, &dcid, &[], 64);
        let greased_ver_initial = build_quic_long_header(0xc0, 0x1a2a_3a4a, &dcid, &[], 64);
        assert!(is_quic_long_header_initial(&draft_initial));
        assert!(is_quic_long_header_initial(&greased_ver_initial));

        // Non-Initial QUIC Long Header packet types must be rejected
        let v1_zero_rtt = build_quic_long_header(0xd0, 0x0000_0001, &dcid, &scid, 64);
        let v1_handshake = build_quic_long_header(0xe0, 0x0000_0001, &dcid, &scid, 64);
        let v1_retry = build_quic_long_header(0xf0, 0x0000_0001, &dcid, &scid, 64);
        let v2_retry = build_quic_long_header(0xc0, 0x6b33_43cf, &dcid, &scid, 64);
        let version_neg = build_quic_long_header(0xc0, 0x0000_0000, &dcid, &scid, 16);
        assert!(!is_quic_long_header_initial(&v1_zero_rtt));
        assert!(!is_quic_long_header_initial(&v1_handshake));
        assert!(!is_quic_long_header_initial(&v1_retry));
        assert!(!is_quic_long_header_initial(&v2_retry));
        assert!(!is_quic_long_header_initial(&version_neg));

        // Short-header 1-RTT, RTP voice, truncated headers, and oversized CIDs
        assert!(!is_quic_long_header_initial(&[0x40; 64]));
        assert!(!is_quic_long_header_initial(&[
            0x80, 0x60, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc
        ]));
        assert!(!is_quic_long_header_initial(&[]));
        assert!(!is_quic_long_header_initial(&[
            0xc0, 0x00, 0x00, 0x00, 0x01
        ]));
        assert!(!is_quic_long_header_initial(&[
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02
        ]));
        let oversized_dcid = [0x33; 21];
        let bad_cid = build_quic_long_header(0xc0, 0x0000_0001, &oversized_dcid, &[], 32);
        assert!(!is_quic_long_header_initial(&bad_cid));
    }

    #[test]
    fn detects_rfc5389_stun_and_never_misclassifies_as_quic() {
        // RFC 5389 STUN Binding Request (20 bytes)
        let mut stun_req = [0u8; 20];
        stun_req[0] = 0x00;
        stun_req[1] = 0x01;
        stun_req[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        stun_req[8..20].copy_from_slice(&[0xab; 12]);
        assert!(is_stun_packet(&stun_req));
        assert!(!is_quic_long_header_initial(&stun_req));

        // RFC 5389 STUN Binding Success Response (32 bytes)
        let mut stun_resp = [0u8; 32];
        stun_resp[0] = 0x01;
        stun_resp[1] = 0x01;
        stun_resp[3] = 0x0c;
        stun_resp[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        assert!(is_stun_packet(&stun_resp));
        assert!(!is_quic_long_header_initial(&stun_resp));

        // Truncated (< 20 bytes) and invalid magic cookie packets must be rejected
        assert!(!is_stun_packet(&stun_req[..19]));
        let mut bad_cookie = stun_req;
        bad_cookie[7] = 0x43;
        assert!(!is_stun_packet(&bad_cookie));

        // Top 2 bits non-zero is not valid STUN (RFC 5389 Section 6)
        let mut non_zero_top_bits = stun_req;
        non_zero_top_bits[0] = 0xc0;
        assert!(!is_stun_packet(&non_zero_top_bits));
        assert!(!is_quic_long_header_initial(&non_zero_top_bits));

        // QUIC Initial packets must never be classified as STUN
        let quic_initial = build_quic_long_header(0xc0, 0x0000_0001, &[0x11; 8], &[], 1200);
        assert!(is_quic_long_header_initial(&quic_initial));
        assert!(!is_stun_packet(&quic_initial));
    }
}
