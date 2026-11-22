//! Dual-stack IPv4 (32-bit) and IPv6 (128-bit) binary radix trie for O(prefix_len)
//! longest-prefix match (LPM). Designed for AWS/GCP published prefix tables and
//! scalable to full BGP tables (>1M prefixes) with sub-microsecond lookup latency.

use crate::addr::{parse_address, ParsedAddr};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct PrefixPayload {
    pub cloud: String,
    pub region: String,
    pub service: String,
    pub prefix: String,
    pub family: &'static str,
    pub source: String,
}

#[derive(Default)]
struct Node {
    children: [u32; 2], // 0 = no child
    value: Option<u32>, // index into payloads vec
}

pub struct DualStackLpm {
    nodes_v4: Vec<Node>,
    nodes_v6: Vec<Node>,
    payloads: Vec<PrefixPayload>,
    pub ipv4_count: u32,
    pub ipv6_count: u32,
}

impl Default for DualStackLpm {
    fn default() -> Self {
        Self::new()
    }
}

impl DualStackLpm {
    pub fn new() -> Self {
        Self {
            nodes_v4: vec![Node::default()],
            nodes_v6: vec![Node::default()],
            payloads: Vec::new(),
            ipv4_count: 0,
            ipv6_count: 0,
        }
    }

    pub fn insert(&mut self, cidr: &str, cloud: String, region: String, service: String, source: String) -> bool {
        let trimmed = cidr.trim();
        let (ip_str, bits_opt) = match trimmed.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (trimmed, None),
        };

        if let Ok(v4) = ip_str.parse::<Ipv4Addr>() {
            let bits: u8 = match bits_opt {
                Some(b) => match b.parse::<u8>() {
                    Ok(v) if v <= 32 => v,
                    _ => return false,
                },
                None => 32,
            };
            let idx = self.payloads.len() as u32;
            self.payloads.push(PrefixPayload {
                cloud,
                region,
                service,
                prefix: trimmed.to_string(),
                family: "ipv4",
                source,
            });
            Self::insert_bits(&mut self.nodes_v4, u32::from(v4) as u128, 32, bits, idx);
            self.ipv4_count += 1;
            return true;
        }

        if let Ok(v6) = ip_str.parse::<Ipv6Addr>() {
            let bits: u8 = match bits_opt {
                Some(b) => match b.parse::<u8>() {
                    Ok(v) if v <= 128 => v,
                    _ => return false,
                },
                None => 128,
            };
            let idx = self.payloads.len() as u32;
            self.payloads.push(PrefixPayload {
                cloud,
                region,
                service,
                prefix: trimmed.to_string(),
                family: "ipv6",
                source,
            });
            Self::insert_bits(&mut self.nodes_v6, u128::from(v6), 128, bits, idx);
            self.ipv6_count += 1;
            return true;
        }

        false
    }

    fn insert_bits(nodes: &mut Vec<Node>, value: u128, total_bits: u8, prefix_len: u8, payload_idx: u32) {
        let mut cur = 0usize;
        for depth in 0..prefix_len {
            let shift = total_bits - 1 - depth;
            let bit = ((value >> shift) & 1) as usize;
            let next = nodes[cur].children[bit];
            if next == 0 {
                let new_idx = nodes.len() as u32;
                nodes.push(Node::default());
                nodes[cur].children[bit] = new_idx;
                cur = new_idx as usize;
            } else {
                cur = next as usize;
            }
        }
        nodes[cur].value = Some(payload_idx);
    }

    fn lookup_bits(nodes: &[Node], value: u128, total_bits: u8) -> Option<u32> {
        let mut cur = 0usize;
        let mut best = nodes[0].value;
        for depth in 0..total_bits {
            let shift = total_bits - 1 - depth;
            let bit = ((value >> shift) & 1) as usize;
            let next = nodes[cur].children[bit];
            if next == 0 {
                break;
            }
            cur = next as usize;
            if nodes[cur].value.is_some() {
                best = nodes[cur].value;
            }
        }
        best
    }

    pub fn lookup(&self, ip: &str) -> Option<&PrefixPayload> {
        let parsed = parse_address(ip)?;
        if parsed.is_unspecified() || parsed.is_loopback() {
            return None;
        }
        let idx = match parsed {
            ParsedAddr::Ipv4 { addr, .. } => Self::lookup_bits(&self.nodes_v4, u32::from(addr) as u128, 32)?,
            ParsedAddr::Ipv6 { addr, .. } => Self::lookup_bits(&self.nodes_v6, u128::from(addr), 128)?,
            _ => return None,
        };
        self.payloads.get(idx as usize)
    }

    pub fn ipv4_nodes(&self) -> u32 {
        self.nodes_v4.len() as u32
    }

    pub fn ipv6_nodes(&self) -> u32 {
        self.nodes_v6.len() as u32
    }
}
