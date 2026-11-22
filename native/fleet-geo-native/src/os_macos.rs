//! Direct macOS XNU kernel socket & process table reader via `libproc`.
//! Eliminates `lsof` + `ps` subprocess spawns.

use crate::addr::from_ipv6_unwrapped;
use crate::{ProcessEntry, SocketEntry};
use std::ffi::CStr;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Map XNU `TSI_S_*` TCP socket states -> RFC 1792 `(name, code)`.
fn macos_tcp_state(state: libc::c_int) -> (&'static str, u32) {
    match state {
        0 => ("closed", 1),
        1 => ("listen", 2),
        2 => ("synSent", 3),
        3 => ("synReceived", 4),
        4 => ("established", 5),
        5 => ("closeWait", 8),
        6 => ("finWait1", 6),
        7 => ("closing", 10),
        8 => ("lastAck", 9),
        9 => ("finWait2", 7),
        10 => ("timeWait", 11),
        _ => ("closed", 1),
    }
}

fn list_all_pids() -> Vec<i32> {
    unsafe {
        let count = libc::proc_listallpids(std::ptr::null_mut(), 0);
        if count <= 0 {
            return Vec::new();
        }
        let mut pids = vec![0i32; (count as usize) + 64];
        let bytes = libc::proc_listallpids(pids.as_mut_ptr() as *mut _, (pids.len() * size_of::<i32>()) as i32);
        if bytes <= 0 {
            return Vec::new();
        }
        pids.truncate((bytes as usize) / size_of::<i32>());
        pids.into_iter().filter(|&p| p > 0).collect()
    }
}

fn bsd_info(pid: i32) -> Option<libc::proc_bsdinfo> {
    unsafe {
        let mut info: libc::proc_bsdinfo = std::mem::zeroed();
        let ret = libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut _,
            size_of::<libc::proc_bsdinfo>() as i32,
        );
        if ret == size_of::<libc::proc_bsdinfo>() as i32 {
            Some(info)
        } else {
            None
        }
    }
}

fn proc_name(info: &libc::proc_bsdinfo) -> Option<String> {
    unsafe {
        let s = CStr::from_ptr(info.pbi_name.as_ptr()).to_string_lossy().trim().to_string();
        if s.is_empty() {
            let c = CStr::from_ptr(info.pbi_comm.as_ptr()).to_string_lossy().trim().to_string();
            if c.is_empty() { None } else { Some(c) }
        } else {
            Some(s)
        }
    }
}

pub fn snapshot_processes() -> Vec<ProcessEntry> {
    list_all_pids()
        .into_iter()
        .filter_map(|pid| {
            let info = bsd_info(pid)?;
            Some(ProcessEntry {
                pid: info.pbi_pid,
                ppid: info.pbi_ppid,
                name: proc_name(&info),
            })
        })
        .collect()
}

pub fn snapshot_sockets() -> Vec<SocketEntry> {
    let mut out = Vec::with_capacity(128);
    for pid in list_all_pids() {
        let name = bsd_info(pid).and_then(|i| proc_name(&i));
        unsafe {
            let buf_size = libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0);
            if buf_size <= 0 {
                continue;
            }
            let fd_count = (buf_size as usize) / size_of::<libc::proc_fdinfo>();
            let mut fds: Vec<libc::proc_fdinfo> = vec![std::mem::zeroed(); fd_count];
            let filled = libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                fds.as_mut_ptr() as *mut _,
                (fds.len() * size_of::<libc::proc_fdinfo>()) as i32,
            );
            if filled <= 0 {
                continue;
            }
            let actual = (filled as usize) / size_of::<libc::proc_fdinfo>();
            for fd in &fds[..actual] {
                if fd.proc_fdtype != libc::PROX_FDTYPE_SOCKET as u32 {
                    continue;
                }
                let mut si: libc::socket_fdinfo = std::mem::zeroed();
                let ret = libc::proc_pidfdinfo(
                    pid,
                    fd.proc_fd,
                    libc::PROC_PIDFDSOCKETINFO,
                    &mut si as *mut _ as *mut _,
                    size_of::<libc::socket_fdinfo>() as i32,
                );
                if ret != size_of::<libc::socket_fdinfo>() as i32 {
                    continue;
                }
                let kind = si.psi.soi_kind;
                let proto = if kind == libc::SOCKINFO_TCP {
                    "tcp"
                } else if kind == libc::SOCKINFO_IN {
                    "udp"
                } else {
                    continue;
                };
                let (in_info, tcp_state) = if kind == libc::SOCKINFO_TCP {
                    let t = si.psi.soi_proto.pri_tcp;
                    (t.tcpsi_ini, Some(t.tcpsi_state))
                } else {
                    (si.psi.soi_proto.pri_in, None)
                };
                let lport = u16::from_be(in_info.insi_lport as u16) as u32;
                let fport = u16::from_be(in_info.insi_fport as u16) as u32;
                let is_v6 = (in_info.insi_vflag & libc::INI_IPV6) != 0;

                let (family, local_ip, rem_ip, local_unspec, rem_unspec) = if is_v6 {
                    let l = from_ipv6_unwrapped(Ipv6Addr::from(in_info.insi_laddr.ina_6.s6_addr), None);
                    let r = from_ipv6_unwrapped(Ipv6Addr::from(in_info.insi_faddr.ina_6.s6_addr), None);
                    let ru = r.is_unspecified() && fport == 0;
                    let fam = if !ru { r.family() } else { l.family() };
                    (fam.to_string(), l.normalized(), r.normalized(), l.is_unspecified(), ru)
                } else {
                    let l = Ipv4Addr::from(in_info.insi_laddr.ina_46.i46a_addr4.s_addr.to_ne_bytes());
                    let r = Ipv4Addr::from(in_info.insi_faddr.ina_46.i46a_addr4.s_addr.to_ne_bytes());
                    let ru = r.is_unspecified() && fport == 0;
                    ("ipv4".to_string(), l.to_string(), r.to_string(), l.is_unspecified(), ru)
                };

                let (state_name, state_code) = match tcp_state {
                    Some(st) => macos_tcp_state(st),
                    None if rem_unspec => ("listen", 2),
                    None => ("established", 5),
                };

                out.push(SocketEntry {
                    protocol: proto.to_string(),
                    family,
                    state: state_name.to_string(),
                    state_code,
                    local_ip,
                    local_port: lport,
                    ip: rem_ip,
                    port: fport,
                    local_unspecified: local_unspec,
                    rem_unspecified: rem_unspec,
                    pid: Some(pid as u32),
                    process: name.clone(),
                });
            }
        }
    }
    out
}
