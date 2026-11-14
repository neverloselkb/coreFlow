use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};
use sysinfo::System;

#[repr(C)]
struct MibTcpRowOwnerPid {
    dw_state: u32,
    dw_local_addr: u32,
    dw_local_port: u32,
    dw_remote_addr: u32,
    dw_remote_port: u32,
    dw_owning_pid: u32,
}

#[repr(C)]
struct MibUdpRowOwnerPid {
    dw_local_addr: u32,
    dw_local_port: u32,
    dw_owning_pid: u32,
}

#[link(name = "iphlpapi")]
extern "system" {
    fn GetExtendedTcpTable(
        pTcpTable: *mut u8,
        pdwSize: *mut u32,
        bOrder: i32,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) -> u32;

    fn GetExtendedUdpTable(
        pUdpTable: *mut u8,
        pdwSize: *mut u32,
        bOrder: i32,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) -> u32;

    fn IcmpCreateFile() -> *mut std::ffi::c_void;
    fn IcmpCloseHandle(icmp_handle: *mut std::ffi::c_void) -> i32;
    fn IcmpSendEcho(
        icmp_handle: *mut std::ffi::c_void,
        destination_address: u32,
        request_data: *const u8,
        request_size: u16,
        request_options: *const u8,
        reply_buffer: *mut u8,
        reply_size: u32,
        timeout: u32,
    ) -> u32;
}

fn icmp_ping(ip: Ipv4Addr, timeout_ms: u32) -> Option<f64> {
    unsafe {
        let handle = IcmpCreateFile();
        if handle.is_null() || handle == ((-1isize) as *mut std::ffi::c_void) {
            return None;
        }
        let send_data = [b'C', b'F', b'P', b'I', b'N', b'G'];
        let reply_size = 1024u32;
        let mut reply_buffer = vec![0u8; reply_size as usize];
        let dest = u32::from_ne_bytes(ip.octets());
        let start = Instant::now();
        let ret = IcmpSendEcho(
            handle,
            dest,
            send_data.as_ptr(),
            send_data.len() as u16,
            std::ptr::null(),
            reply_buffer.as_mut_ptr(),
            reply_size,
            timeout_ms,
        );
        IcmpCloseHandle(handle);
        if ret > 0 {
            Some(start.elapsed().as_secs_f64() * 1000.0)
        } else {
            None
        }
    }
}

fn tcp_ping(ip: Ipv4Addr, port: u16) -> Option<f64> {
    let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
    let start = Instant::now();
    match TcpStream::connect_timeout(&addr, Duration::from_millis(1500)) {
        Ok(_) => Some(start.elapsed().as_secs_f64() * 1000.0),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            Some(start.elapsed().as_secs_f64() * 1000.0)
        }
        _ => None,
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    if o[0] == 0 || o[0] == 127 || (o[0] == 169 && o[1] == 254) {
        return false;
    }
    if o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168) {
        return false;
    }
    if o[0] >= 224 {
        return false;
    }
    true
}

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut std::ffi::c_void;
    fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    fn QueryFullProcessImageNameW(hProcess: *mut std::ffi::c_void, dwFlags: u32, lpExeName: *mut u16, lpdwSize: *mut u32) -> i32;
}

fn get_process_name(pid: u32) -> String {
    unsafe {
        let handle = OpenProcess(0x1000, 0, pid); // PROCESS_QUERY_LIMITED_INFORMATION
        if handle.is_null() {
            return format!("PID:{}", pid);
        }
        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;
        let ret = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size);
        CloseHandle(handle);
        if ret != 0 {
            let full = String::from_utf16_lossy(&buf[..size as usize]);
            std::path::Path::new(&full)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or(full)
        } else {
            format!("PID:{}", pid)
        }
    }
}

fn main() {
    println!("=== Searching for Division 2 / Game processes ===");
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut target_pids = Vec::new();
    for (pid, proc_) in sys.processes() {
        let name = proc_.name().to_string_lossy().to_lowercase();
        let exe = proc_.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
        if name.contains("division") || name.contains("ubisoft") || name.contains("uplay") || name.contains("easyanti") {
            println!("Found matching process: PID {} | Name: {} | Exe: {}", pid.as_u32(), proc_.name().to_string_lossy(), exe);
            target_pids.push((pid.as_u32(), proc_.name().to_string_lossy().to_string()));
        }
    }

    if target_pids.is_empty() {
        println!("No process containing 'division' found. Listing top CPU/memory processes:");
        let mut all: Vec<_> = sys.processes().iter().collect();
        all.sort_by(|a, b| b.1.memory().cmp(&a.1.memory()));
        for (pid, p) in all.iter().take(15) {
            println!("PID {} | Mem: {:.1} MB | Name: {}", pid.as_u32(), p.memory() as f64 / 1_048_576.0, p.name().to_string_lossy());
            let lower = p.name().to_string_lossy().to_lowercase();
            if lower.ends_with(".exe") && !lower.contains("chrome") && !lower.contains("code") && !lower.contains("antigravity") {
                target_pids.push((pid.as_u32(), p.name().to_string_lossy().to_string()));
            }
        }
    }

    // Now inspect TCP table
    println!("\n=== Inspecting TCP connections ===");
    unsafe {
        let mut size = 0u32;
        GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, 2, 5, 0);
        let mut buf = vec![0u8; size as usize];
        if GetExtendedTcpTable(buf.as_mut_ptr(), &mut size, 0, 2, 5, 0) == 0 {
            let num_entries = *(buf.as_ptr() as *const u32);
            let row_ptr = buf.as_ptr().add(4) as *const MibTcpRowOwnerPid;
            println!("Total TCP entries in table: {}", num_entries);
            for i in 0..num_entries as usize {
                let row = &*row_ptr.add(i);
                let pid = row.dw_owning_pid;
                let r_ip = Ipv4Addr::from(row.dw_remote_addr.to_ne_bytes());
                let r_port = u16::from_be(row.dw_remote_port as u16);
                let l_port = u16::from_be(row.dw_local_port as u16);
                let state_str = match row.dw_state {
                    5 => "ESTABLISHED",
                    2 => "LISTENING",
                    1 => "CLOSED",
                    3 => "SYN_SENT",
                    4 => "SYN_RCVD",
                    8 => "CLOSE_WAIT",
                    11 => "TIME_WAIT",
                    _ => "OTHER",
                };
                if is_public_ipv4(r_ip) && row.dw_state == 5 {
                    let p_name = get_process_name(pid);
                    println!("PID {} ({}) | Local: :{} | Remote: {}:{} | State: {}", pid, p_name, l_port, r_ip, r_port, state_str);
                    let icmp = icmp_ping(r_ip, 800);
                    let tcp = tcp_ping(r_ip, r_port);
                    println!("   -> ICMP: {:?} ms | TCP handshake: {:?} ms", icmp, tcp);
                }
            }
        } else {
            println!("GetExtendedTcpTable failed");
        }
    }

    // Inspect UDP table
    println!("\n=== Inspecting UDP ports/sockets ===");
    unsafe {
        let mut size = 0u32;
        GetExtendedUdpTable(std::ptr::null_mut(), &mut size, 0, 2, 1, 0);
        let mut buf = vec![0u8; size as usize];
        if GetExtendedUdpTable(buf.as_mut_ptr(), &mut size, 0, 2, 1, 0) == 0 {
            let num_entries = *(buf.as_ptr() as *const u32);
            let row_ptr = buf.as_ptr().add(4) as *const MibUdpRowOwnerPid;
            for i in 0..num_entries as usize {
                let row = &*row_ptr.add(i);
                let pid = row.dw_owning_pid;
                let is_target = target_pids.iter().any(|(p, _)| *p == pid);
                if is_target {
                    let l_port = u16::from_be(row.dw_local_port as u16);
                    let proc_name = target_pids.iter().find(|(p, _)| *p == pid).map(|(_, n)| n.as_str()).unwrap_or("");
                    println!("UDP Bound: PID {} ({}) | Local port: :{}", pid, proc_name, l_port);
                }
            }
        }
    }
}
