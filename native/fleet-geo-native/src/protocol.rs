//! Zero-copy, bounds-checked TLS ClientHello SNI and DNS wire-format question parsers.

/// Extract the SNI hostname from a cleartext TLS 1.2/1.3 ClientHello record.
pub fn parse_client_hello_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 43 || buf[0] != 0x16 || buf[5] != 0x01 {
        return None;
    }
    let mut p: usize = 9 + 2 + 32; // record hdr(5) + handshake hdr(4) + version(2) + random(32)
    if p >= buf.len() {
        return None;
    }
    p = p.checked_add(1 + buf[p] as usize)?; // session id
    if p + 2 > buf.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p = p.checked_add(2 + cipher_len)?;
    if p >= buf.len() {
        return None;
    }
    p = p.checked_add(1 + buf[p] as usize)?; // compression methods
    if p + 2 > buf.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    let end = buf.len().min(p.saturating_add(ext_len));

    while p + 4 <= end {
        let ext_type = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let len = u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize;
        p += 4;
        if p + len > end {
            return None;
        }
        if ext_type == 0x0000 {
            // server_name extension: list_len(2), name_type(1), name_len(2), name
            if len < 5 || buf[p + 2] != 0 {
                return None;
            }
            let name_len = u16::from_be_bytes([buf[p + 3], buf[p + 4]]) as usize;
            if 5 + name_len > len {
                return None;
            }
            let raw = std::str::from_utf8(&buf[p + 5..p + 5 + name_len]).ok()?;
            if !raw.is_empty()
                && raw
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            {
                return Some(raw.to_ascii_lowercase());
            }
            return None;
        }
        p += len;
    }
    None
}

/// Extract the question name from a single-question UDP DNS query packet.
pub fn parse_dns_question(buf: &[u8]) -> Option<String> {
    if buf.len() < 17 {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if (flags & 0x8000) != 0 {
        return None; // response, not a query
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount != 1 {
        return None;
    }
    let mut labels = Vec::new();
    let mut p = 12usize;
    while p < buf.len() && buf[p] != 0 {
        let n = buf[p] as usize;
        if n > 63 || p + 1 + n > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(&buf[p + 1..p + 1 + n]).ok()?;
        labels.push(label);
        p += 1 + n;
    }
    if p >= buf.len() || buf[p] != 0 || labels.len() < 2 {
        return None;
    }
    let name = labels.join(".").to_ascii_lowercase();
    let last = labels.last()?;
    if name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
        && last.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        Some(name)
    } else {
        None
    }
}
