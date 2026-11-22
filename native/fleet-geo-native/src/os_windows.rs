//! Direct Windows kernel RFC 1792 socket & process table reader via IP Helper API
//! (`GetExtendedTcpTable`, `GetExtendedUdpTable`) and Toolhelp32 (`CreateToolhelp32Snapshot`).
//! Eliminates `netstat` + PowerShell subprocess spawns.

use crate::addr::from_ipv6_unwrapped;
use crate::{ProcessEntry, SocketEntry};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, INVALID_HANDLE_VALUE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

/// Map Win32 `MIB_TCP_STATE_*` -> RFC 1792 `(name, code)`.
/// Note: Win32 has CLOSING=9, LAST_ACK=10; RFC 1792 has lastAck(9), closing(10).
fn win_tcp_state(state: u32) -> (&'static str, u32) {
    match state {
        1 => ("closed", 1),
        2 => ("listen", 2),
        3 => ("synSent", 3),
        4 => ("synReceived", 4),
        5 => ("established", 5),
        6 => ("finWait1", 6),
        7 => ("finWait2", 7),
        8 => ("closeWait", 8),
        9 => ("closing", 10),
        10 => ("lastAck", 9),
        11 => ("timeWait", 11),
        12 => ("closed", 1), // DELETE_TCB
        _ => ("closed", 1),
    }
}

fn ntohs_dw(port: u32) -> u32 {
    u16::from_be(port as u16) as u32
}

pub fn snapshot_processes() -> Vec<ProcessEntry> {
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                out.push(ProcessEntry {
                    pid: entry.th32ProcessID,
                    ppid: entry.th32ParentProcessID,
                    name: if name.is_empty() { None } else { Some(name) },
                });
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

pub fn snapshot_sockets() -> Vec<SocketEntry> {
    let proc_names: HashMap<u32, String> = snapshot_processes()
        .into_iter()
        .filter_map(|p| p.name.map(|n| (p.pid, n)))
        .collect();

    let mut out = Vec::with_capacity(128);
    read_tcp_v4(&proc_names, &mut out);
    read_tcp_v6(&proc_names, &mut out);
    read_udp_v4(&proc_names, &mut out);
    read_udp_v6(&proc_names, &mut out);
    out
}

fn read_tcp_v4(procs: &HashMap<u32, String>, out: &mut Vec<SocketEntry>) {
    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        if size == 0 {
            return;
        }
        let mut buf = vec![0u8; size as usize];
        let mut ret = GetExtendedTcpTable(buf.as_mut_ptr() as *mut _, &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        if ret == ERROR_INSUFFICIENT_BUFFER {
            buf.resize(size as usize, 0);
            ret = GetExtendedTcpTable(buf.as_mut_ptr() as *mut _, &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        }
        if ret != NO_ERROR {
            return;
        }
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        for r in rows {
            let local = Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes());
            let rem = Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes());
            let local_port = ntohs_dw(r.dwLocalPort);
            let rem_port = if r.dwState == 2 { 0 } else { ntohs_dw(r.dwRemotePort) };
            let (state_name, state_code) = win_tcp_state(r.dwState);
            let rem_unspec = rem.is_unspecified() && rem_port == 0;
            out.push(SocketEntry {
                protocol: "tcp".to_string(),
                family: "ipv4".to_string(),
                state: state_name.to_string(),
                state_code,
                local_ip: local.to_string(),
                local_port,
                ip: rem.to_string(),
                port: rem_port,
                local_unspecified: local.is_unspecified(),
                rem_unspecified: rem_unspec,
                pid: Some(r.dwOwningPid),
                process: procs.get(&r.dwOwningPid).cloned(),
            });
        }
    }
}

fn read_tcp_v6(procs: &HashMap<u32, String>, out: &mut Vec<SocketEntry>) {
    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        if size == 0 {
            return;
        }
        let mut buf = vec![0u8; size as usize];
        let mut ret = GetExtendedTcpTable(buf.as_mut_ptr() as *mut _, &mut size, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        if ret == ERROR_INSUFFICIENT_BUFFER {
            buf.resize(size as usize, 0);
            ret = GetExtendedTcpTable(buf.as_mut_ptr() as *mut _, &mut size, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        }
        if ret != NO_ERROR {
            return;
        }
        let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr() as *const MIB_TCP6ROW_OWNER_PID, table.dwNumEntries as usize);
        for r in rows {
            let local = from_ipv6_unwrapped(Ipv6Addr::from(r.ucLocalAddr), None);
            let rem = from_ipv6_unwrapped(Ipv6Addr::from(r.ucRemoteAddr), None);
            let local_port = ntohs_dw(r.dwLocalPort);
            let rem_port = if r.dwState == 2 { 0 } else { ntohs_dw(r.dwRemotePort) };
            let (state_name, state_code) = win_tcp_state(r.dwState);
            let rem_unspec = rem.is_unspecified() && rem_port == 0;
            let family = if !rem_unspec { rem.family() } else { local.family() };
            out.push(SocketEntry {
                protocol: "tcp".to_string(),
                family: family.to_string(),
                state: state_name.to_string(),
                state_code,
                local_ip: local.normalized(),
                local_port,
                ip: rem.normalized(),
                port: rem_port,
                local_unspecified: local.is_unspecified(),
                rem_unspecified: rem_unspec,
                pid: Some(r.dwOwningPid),
                process: procs.get(&r.dwOwningPid).cloned(),
            });
        }
    }
}

fn read_udp_v4(procs: &HashMap<u32, String>, out: &mut Vec<SocketEntry>) {
    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedUdpTable(std::ptr::null_mut(), &mut size, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0);
        if size == 0 {
            return;
        }
        let mut buf = vec![0u8; size as usize];
        let mut ret = GetExtendedUdpTable(buf.as_mut_ptr() as *mut _, &mut size, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0);
        if ret == ERROR_INSUFFICIENT_BUFFER {
            buf.resize(size as usize, 0);
            ret = GetExtendedUdpTable(buf.as_mut_ptr() as *mut _, &mut size, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0);
        }
        if ret != NO_ERROR {
            return;
        }
        let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr() as *const MIB_UDPROW_OWNER_PID, table.dwNumEntries as usize);
        for r in rows {
            let local = Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes());
            let local_port = ntohs_dw(r.dwLocalPort);
            out.push(SocketEntry {
                protocol: "udp".to_string(),
                family: "ipv4".to_string(),
                state: "listen".to_string(),
                state_code: 2,
                local_ip: local.to_string(),
                local_port,
                ip: "0.0.0.0".to_string(),
                port: 0,
                local_unspecified: local.is_unspecified(),
                rem_unspecified: true,
                pid: Some(r.dwOwningPid),
                process: procs.get(&r.dwOwningPid).cloned(),
            });
        }
    }
}

fn read_udp_v6(procs: &HashMap<u32, String>, out: &mut Vec<SocketEntry>) {
    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedUdpTable(std::ptr::null_mut(), &mut size, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0);
        if size == 0 {
            return;
        }
        let mut buf = vec![0u8; size as usize];
        let mut ret = GetExtendedUdpTable(buf.as_mut_ptr() as *mut _, &mut size, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0);
        if ret == ERROR_INSUFFICIENT_BUFFER {
            buf.resize(size as usize, 0);
            ret = GetExtendedUdpTable(buf.as_mut_ptr() as *mut _, &mut size, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0);
        }
        if ret != NO_ERROR {
            return;
        }
        let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr() as *const MIB_UDP6ROW_OWNER_PID, table.dwNumEntries as usize);
        for r in rows {
            let local = from_ipv6_unwrapped(Ipv6Addr::from(r.ucLocalAddr), None);
            let local_port = ntohs_dw(r.dwLocalPort);
            out.push(SocketEntry {
                protocol: "udp".to_string(),
                family: local.family().to_string(),
                state: "listen".to_string(),
                state_code: 2,
                local_ip: local.normalized(),
                local_port,
                ip: "::".to_string(),
                port: 0,
                local_unspecified: local.is_unspecified(),
                rem_unspecified: true,
                pid: Some(r.dwOwningPid),
                process: procs.get(&r.dwOwningPid).cloned(),
            });
        }
    }
}
