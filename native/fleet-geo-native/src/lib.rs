//! Encore-style Rust N-API native core for `fleet-geo-mcp`.
//!
//! Runs directly inside the Node.js process over Node-API with zero JS runtime
//! dependencies, providing:
//!   - Kernel-native RFC 1792 TCP/UDP socket & process snapshots (zero subprocesses)
//!   - Dual-stack IPv4 + IPv6 binary radix trie for sub-microsecond LPM prefix matching
//!   - Zero-copy TLS ClientHello SNI, DNS question, and dual-stack address parsers

mod addr;
mod lpm;
mod protocol;

#[cfg(target_os = "linux")]
mod os_linux;
#[cfg(target_os = "macos")]
mod os_macos;
#[cfg(target_os = "windows")]
mod os_windows;

use lpm::DualStackLpm;
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

#[napi(object)]
pub struct RuntimeInfo {
    pub engine: String,
    pub version: String,
    pub platform: String,
    pub arch: String,
    pub capabilities: Vec<String>,
}

#[napi(object)]
#[derive(Clone)]
pub struct SocketEntry {
    pub protocol: String,
    pub family: String,
    pub state: String,
    pub state_code: u32,
    pub local_ip: String,
    pub local_port: u32,
    pub ip: String,
    pub port: u32,
    pub local_unspecified: bool,
    pub rem_unspecified: bool,
    pub pid: Option<u32>,
    pub process: Option<String>,
}

#[napi(object)]
pub struct ProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    pub name: Option<String>,
}

#[napi(object)]
pub struct NormalizedAddress {
    pub family: String,
    pub normalized: String,
    pub expanded_hex32: Option<String>,
    pub is_unspecified: bool,
    pub is_loopback: bool,
    pub is_private: bool,
    pub zone: Option<String>,
}

#[napi(object)]
pub struct PrefixEntryInput {
    pub cidr: String,
    pub cloud: String,
    pub region: String,
    pub service: String,
    pub source: String,
}

#[napi(object)]
pub struct PrefixMatch {
    pub cloud: String,
    pub region: String,
    pub service: String,
    pub prefix: String,
    pub family: String,
    pub source: String,
}

#[napi(object)]
pub struct PrefixTableStats {
    pub ipv4_count: u32,
    pub ipv6_count: u32,
    pub ipv4_nodes: u32,
    pub ipv6_nodes: u32,
}

#[napi]
pub fn runtime_info() -> RuntimeInfo {
    RuntimeInfo {
        engine: "rust-napi".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        capabilities: vec![
            "kernel-sockets".to_string(),
            "kernel-processes".to_string(),
            "lpm-radix-trie".to_string(),
            "sni-dns-parser".to_string(),
        ],
    }
}

#[napi]
pub fn snapshot_sockets() -> Vec<SocketEntry> {
    #[cfg(target_os = "linux")]
    {
        os_linux::snapshot_sockets()
    }
    #[cfg(target_os = "windows")]
    {
        os_windows::snapshot_sockets()
    }
    #[cfg(target_os = "macos")]
    {
        os_macos::snapshot_sockets()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Vec::new()
    }
}

#[napi]
pub fn snapshot_processes() -> Vec<ProcessEntry> {
    #[cfg(target_os = "linux")]
    {
        os_linux::snapshot_processes()
    }
    #[cfg(target_os = "windows")]
    {
        os_windows::snapshot_processes()
    }
    #[cfg(target_os = "macos")]
    {
        os_macos::snapshot_processes()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Vec::new()
    }
}

#[napi]
pub fn normalize_address(raw: String) -> Option<NormalizedAddress> {
    let a = addr::parse_address(&raw)?;
    Some(NormalizedAddress {
        family: a.family().to_string(),
        normalized: a.normalized(),
        expanded_hex32: a.expanded_hex32(),
        is_unspecified: a.is_unspecified(),
        is_loopback: a.is_loopback(),
        is_private: a.is_private(),
        zone: a.zone(),
    })
}

#[napi]
pub fn parse_client_hello_sni(buf: Buffer) -> Option<String> {
    protocol::parse_client_hello_sni(buf.as_ref())
}

#[napi]
pub fn parse_dns_question(buf: Buffer) -> Option<String> {
    protocol::parse_dns_question(buf.as_ref())
}

#[napi]
pub struct PrefixTable {
    inner: DualStackLpm,
}

#[napi]
impl PrefixTable {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: DualStackLpm::new(),
        }
    }

    #[napi]
    pub fn insert_batch(&mut self, entries: Vec<PrefixEntryInput>) -> u32 {
        let mut added = 0u32;
        for e in entries {
            if self.inner.insert(&e.cidr, e.cloud, e.region, e.service, e.source) {
                added += 1;
            }
        }
        added
    }

    #[napi]
    pub fn lookup(&self, ip: String) -> Option<PrefixMatch> {
        let p = self.inner.lookup(&ip)?;
        Some(PrefixMatch {
            cloud: p.cloud.clone(),
            region: p.region.clone(),
            service: p.service.clone(),
            prefix: p.prefix.clone(),
            family: p.family.to_string(),
            source: p.source.clone(),
        })
    }

    #[napi]
    pub fn stats(&self) -> PrefixTableStats {
        PrefixTableStats {
            ipv4_count: self.inner.ipv4_count,
            ipv6_count: self.inner.ipv6_count,
            ipv4_nodes: self.inner.ipv4_nodes(),
            ipv6_nodes: self.inner.ipv6_nodes(),
        }
    }
}
