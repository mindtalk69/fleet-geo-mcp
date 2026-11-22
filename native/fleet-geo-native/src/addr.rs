//! Dual-stack IPv4 / IPv6 / IPX / Unspecified address primitives (RFC 1792).

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub enum ParsedAddr {
    Ipv4 {
        addr: Ipv4Addr,
        zone: Option<String>,
    },
    Ipv6 {
        addr: Ipv6Addr,
        zone: Option<String>,
    },
    Ipx {
        normalized: String,
        is_unspecified: bool,
    },
    Unspecified,
}

impl ParsedAddr {
    pub fn family(&self) -> &'static str {
        match self {
            ParsedAddr::Ipv4 { .. } => "ipv4",
            ParsedAddr::Ipv6 { .. } => "ipv6",
            ParsedAddr::Ipx { .. } => "ipx",
            ParsedAddr::Unspecified => "unspecified",
        }
    }

    pub fn normalized(&self) -> String {
        match self {
            ParsedAddr::Ipv4 { addr, .. } => addr.to_string(),
            ParsedAddr::Ipv6 { addr, .. } => addr.to_string(),
            ParsedAddr::Ipx { normalized, .. } => normalized.clone(),
            ParsedAddr::Unspecified => "*".to_string(),
        }
    }

    pub fn expanded_hex32(&self) -> Option<String> {
        match self {
            ParsedAddr::Ipv6 { addr, .. } => Some(format!("{:032x}", u128::from(*addr))),
            _ => None,
        }
    }

    pub fn is_unspecified(&self) -> bool {
        match self {
            ParsedAddr::Ipv4 { addr, .. } => addr.is_unspecified(),
            ParsedAddr::Ipv6 { addr, .. } => addr.is_unspecified(),
            ParsedAddr::Ipx { is_unspecified, .. } => *is_unspecified,
            ParsedAddr::Unspecified => true,
        }
    }

    pub fn is_loopback(&self) -> bool {
        match self {
            ParsedAddr::Ipv4 { addr, .. } => addr.is_loopback(),
            ParsedAddr::Ipv6 { addr, .. } => addr.is_loopback(),
            _ => false,
        }
    }

    pub fn is_private(&self) -> bool {
        match self {
            ParsedAddr::Ipv4 { addr, .. } => {
                let o = addr.octets();
                addr.is_loopback()
                    || addr.is_private()
                    || addr.is_link_local()
                    || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT / Tailscale 100.64.0.0/10
            }
            ParsedAddr::Ipv6 { addr, .. } => {
                let seg0 = addr.segments()[0];
                addr.is_loopback() || (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80
            }
            ParsedAddr::Ipx { .. } => true,
            ParsedAddr::Unspecified => false,
        }
    }

    pub fn zone(&self) -> Option<String> {
        match self {
            ParsedAddr::Ipv4 { zone, .. } | ParsedAddr::Ipv6 { zone, .. } => zone.clone(),
            _ => None,
        }
    }
}

/// Unwrap IPv4-mapped IPv6 (`::ffff:a.b.c.d`) into canonical IPv4.
pub fn from_ipv6_unwrapped(v6: Ipv6Addr, zone: Option<String>) -> ParsedAddr {
    if let Some(v4) = v6.to_ipv4_mapped() {
        ParsedAddr::Ipv4 { addr: v4, zone }
    } else {
        ParsedAddr::Ipv6 { addr: v6, zone }
    }
}

pub fn parse_address(raw: &str) -> Option<ParsedAddr> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed == "*" {
        return Some(ParsedAddr::Unspecified);
    }
    if trimmed.eq_ignore_ascii_case("localhost") {
        return Some(ParsedAddr::Ipv4 {
            addr: Ipv4Addr::LOCALHOST,
            zone: None,
        });
    }

    // RFC 1792 IpxAddress: nnnnnnnn:mmmmmmmmmmmm (4-byte net : 6-byte node)
    if trimmed.len() == 21 && trimmed.as_bytes()[8] == b':' {
        let (net, node) = (&trimmed[..8], &trimmed[9..]);
        if net.bytes().all(|b| b.is_ascii_hexdigit()) && node.bytes().all(|b| b.is_ascii_hexdigit()) {
            let norm = format!("{}:{}", net.to_ascii_lowercase(), node.to_ascii_lowercase());
            let is_unspec = norm == "00000000:000000000000";
            return Some(ParsedAddr::Ipx {
                normalized: norm,
                is_unspecified: is_unspec,
            });
        }
    }

    // Strip optional brackets and %zone suffix (e.g. "[fe80::1]%eno1" or "[fe80::1%eno1]").
    let mut zone: Option<String> = None;
    let mut s = trimmed;
    if let Some(idx) = s.rfind('%') {
        if !s[idx..].contains(']') {
            zone = Some(s[idx + 1..].to_string());
            s = &s[..idx];
        }
    }
    if s.starts_with('[') && s.ends_with(']') {
        s = &s[1..s.len() - 1];
    }
    if let Some(idx) = s.rfind('%') {
        if zone.is_none() {
            zone = Some(s[idx + 1..].to_string());
        }
        s = &s[..idx];
    }

    if let Ok(v4) = s.parse::<Ipv4Addr>() {
        return Some(ParsedAddr::Ipv4 { addr: v4, zone });
    }
    if let Ok(v6) = s.parse::<Ipv6Addr>() {
        return Some(from_ipv6_unwrapped(v6, zone));
    }
    None
}
