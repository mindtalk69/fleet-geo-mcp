//! Direct Linux kernel RFC 1792 socket & process table reader via /proc/net/* and /proc/<pid>.
//! Zero subprocesses (replaces `ss` + `ps`), unprivileged, sub-millisecond on typical hosts.

use crate::addr::from_ipv6_unwrapped;
use crate::{ProcessEntry, SocketEntry};
use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Map Linux kernel `include/net/tcp_states.h` hex code -> RFC 1792 `(name, code)`.
fn linux_tcp_state(hex: &str) -> Option<(&'static str, u32)> {
    match u8::from_str_radix(hex, 16).ok()? {
        0x01 => Some(("established", 5)),
        0x02 => Some(("synSent", 3)),
        0x03 => Some(("synReceived", 4)),
        0x04 => Some(("finWait1", 6)),
        0x05 => Some(("finWait2", 7)),
        0x06 => Some(("timeWait", 11)),
        0x07 => Some(("closed", 1)),
        0x08 => Some(("closeWait", 8)),
        0x09 => Some(("lastAck", 9)),
        0x0A => Some(("listen", 2)),
        0x0B => Some(("closing", 10)),
        0x0C => Some(("synReceived", 4)), // TCP_NEW_SYN_RECV
        _ => None,
    }
}

fn parse_proc_ipv4(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let v = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(v.to_ne_bytes()))
}

fn parse_proc_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let word = u32::from_str_radix(&hex[i * 8..(i + 1) * 8], 16).ok()?;
        let bytes = word.to_ne_bytes();
        octets[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }
    Some(Ipv6Addr::from(octets))
}

fn parse_proc_endpoint_v4(tok: &str) -> Option<(Ipv4Addr, u32)> {
    let (h, p) = tok.split_once(':')?;
    let ip = parse_proc_ipv4(h)?;
    let port = u32::from_str_radix(p, 16).ok()?;
    Some((ip, port))
}

fn parse_proc_endpoint_v6(tok: &str) -> Option<(Ipv6Addr, u32)> {
    let (h, p) = tok.split_once(':')?;
    let ip = parse_proc_ipv6(h)?;
    let port = u32::from_str_radix(p, 16).ok()?;
    Some((ip, port))
}

/// Scan /proc/<pid>/fd to map socket inode -> (pid, comm). Silently skips unreadable PIDs.
fn scan_socket_inodes() -> HashMap<u64, (u32, String)> {
    let mut map = HashMap::new();
    let Ok(proc_dir) = fs::read_dir("/proc") else {
        return map;
    };
    for entry in proc_dir.flatten() {
        let Ok(fname) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = fname.parse::<u32>() else {
            continue;
        };
        let fd_path = entry.path().join("fd");
        let Ok(fds) = fs::read_dir(&fd_path) else {
            continue;
        };
        let mut comm: Option<String> = None;
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let Some(s) = target.to_str() else {
                continue;
            };
            if let Some(rest) = s.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')) {
                if let Ok(inode) = rest.parse::<u64>() {
                    let name = comm.get_or_insert_with(|| {
                        fs::read_to_string(entry.path().join("comm"))
                            .map(|c| c.trim().to_string())
                            .unwrap_or_default()
                    });
                    map.entry(inode).or_insert_with(|| (pid, name.clone()));
                }
            }
        }
    }
    map
}

fn parse_proc_net_v4(
    path: &str,
    protocol: &str,
    inodes: &HashMap<u64, (u32, String)>,
    out: &mut Vec<SocketEntry>,
) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let Some((local_ip, local_port)) = parse_proc_endpoint_v4(cols[1]) else {
            continue;
        };
        let Some((rem_ip, rem_port)) = parse_proc_endpoint_v4(cols[2]) else {
            continue;
        };
        let rem_unspec = rem_ip.is_unspecified() && rem_port == 0;
        let (state_name, state_code) = if protocol == "tcp" {
            let Some(st) = linux_tcp_state(cols[3]) else {
                continue;
            };
            st
        } else if rem_unspec {
            ("listen", 2)
        } else {
            ("established", 5)
        };
        let inode = cols[9].parse::<u64>().unwrap_or(0);
        let (pid, process) = inodes
            .get(&inode)
            .map(|(p, n)| (Some(*p), if n.is_empty() { None } else { Some(n.clone()) }))
            .unwrap_or((None, None));

        out.push(SocketEntry {
            protocol: protocol.to_string(),
            family: "ipv4".to_string(),
            state: state_name.to_string(),
            state_code,
            local_ip: local_ip.to_string(),
            local_port,
            ip: rem_ip.to_string(),
            port: rem_port,
            local_unspecified: local_ip.is_unspecified(),
            rem_unspecified: rem_unspec,
            pid,
            process,
        });
    }
}

fn parse_proc_net_v6(
    path: &str,
    protocol: &str,
    inodes: &HashMap<u64, (u32, String)>,
    out: &mut Vec<SocketEntry>,
) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let Some((raw_local, local_port)) = parse_proc_endpoint_v6(cols[1]) else {
            continue;
        };
        let Some((raw_rem, rem_port)) = parse_proc_endpoint_v6(cols[2]) else {
            continue;
        };
        let local = from_ipv6_unwrapped(raw_local, None);
        let rem = from_ipv6_unwrapped(raw_rem, None);
        let rem_unspec = rem.is_unspecified() && rem_port == 0;
        let (state_name, state_code) = if protocol == "tcp" {
            let Some(st) = linux_tcp_state(cols[3]) else {
                continue;
            };
            st
        } else if rem_unspec {
            ("listen", 2)
        } else {
            ("established", 5)
        };
        let family = if !rem_unspec {
            rem.family()
        } else {
            local.family()
        };
        let inode = cols[9].parse::<u64>().unwrap_or(0);
        let (pid, process) = inodes
            .get(&inode)
            .map(|(p, n)| (Some(*p), if n.is_empty() { None } else { Some(n.clone()) }))
            .unwrap_or((None, None));

        out.push(SocketEntry {
            protocol: protocol.to_string(),
            family: family.to_string(),
            state: state_name.to_string(),
            state_code,
            local_ip: local.normalized(),
            local_port,
            ip: rem.normalized(),
            port: rem_port,
            local_unspecified: local.is_unspecified(),
            rem_unspecified: rem_unspec,
            pid,
            process,
        });
    }
}

pub fn snapshot_sockets() -> Vec<SocketEntry> {
    let inodes = scan_socket_inodes();
    let mut out = Vec::with_capacity(128);
    parse_proc_net_v4("/proc/net/tcp", "tcp", &inodes, &mut out);
    parse_proc_net_v6("/proc/net/tcp6", "tcp", &inodes, &mut out);
    parse_proc_net_v4("/proc/net/udp", "udp", &inodes, &mut out);
    parse_proc_net_v6("/proc/net/udp6", "udp", &inodes, &mut out);
    out
}

pub fn snapshot_processes() -> Vec<ProcessEntry> {
    let mut out = Vec::with_capacity(256);
    let Ok(proc_dir) = fs::read_dir("/proc") else {
        return out;
    };
    for entry in proc_dir.flatten() {
        let Ok(fname) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = fname.parse::<u32>() else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // Format: "<pid> (<comm with spaces/parens>) <state> <ppid> ..."
        let Some(open) = stat.find('(') else {
            continue;
        };
        let Some(close) = stat.rfind(')') else {
            continue;
        };
        if close <= open {
            continue;
        }
        let comm = stat[open + 1..close].to_string();
        let after = stat[close + 1..].trim_start();
        let mut fields = after.split_whitespace();
        let _state = fields.next();
        let Some(ppid_str) = fields.next() else {
            continue;
        };
        if let Ok(ppid) = ppid_str.parse::<u32>() {
            out.push(ProcessEntry {
                pid,
                ppid,
                name: if comm.is_empty() { None } else { Some(comm) },
            });
        }
    }
    out
}
