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

/// Extracts the `Host` header hostname and the byte offset of its midpoint in a plain HTTP request.
pub fn extract_http_host_split(buf: &[u8]) -> Option<(String, usize)> {
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
                let host_start = offset + 5 + ws;
                let split_at = (host_start + (host_only.len() / 2).max(1))
                    .clamp(1, buf.len().saturating_sub(1));
                return Some((host_only, split_at));
            }
        }
        offset += line.len() + 2;
    }
    None
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
}
