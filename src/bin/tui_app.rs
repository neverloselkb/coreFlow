#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
#![cfg_attr(not(target_os = "windows"), allow(dead_code, unused_imports, unused_variables))]

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use sysinfo::{DiskKind, Disks, Networks, System};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

pub trait CommandNoWindow {
    fn no_window(&mut self) -> &mut Self;
}

#[cfg(target_os = "windows")]
impl CommandNoWindow for Command {
    fn no_window(&mut self) -> &mut Self {
        self.creation_flags(CREATE_NO_WINDOW)
    }
}

#[cfg(not(target_os = "windows"))]
impl CommandNoWindow for Command {
    fn no_window(&mut self) -> &mut Self {
        self
    }
}

const CREATE_NO_WINDOW: u32 = 0x08000000;
const HKEY_CURRENT_USER: isize = 0x80000001u32 as i32 as isize;
const HKEY_LOCAL_MACHINE: isize = 0x80000002u32 as i32 as isize;
const KEY_READ: u32 = 0x20019;
const KEY_SET_VALUE: u32 = 0x0002;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;
const MAX_HTTP_BODY_BYTES: usize = 10 * 1024 * 1024; // 10 MB 상한 (OOM DoS 방지)
const APP_ICON_ICO: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/coreflow.ico"));

#[cfg(target_os = "windows")]
#[link(name = "Kernel32")]
extern "system" {
    fn GetModuleHandleW(lpModuleName: *const u16) -> isize;
}

#[cfg(target_os = "windows")]
#[link(name = "User32")]
extern "system" {
    fn FindWindowW(lpClassName: *const u16, lpWindowName: *const u16) -> isize;
    fn FindWindowExW(
        hWndParent: isize,
        hWndChildAfter: isize,
        lpszClass: *const u16,
        lpszWindow: *const u16,
    ) -> isize;
    fn IsWindowVisible(hWnd: isize) -> i32;
    fn IsZoomed(hWnd: isize) -> i32;
    fn ShowWindow(hWnd: isize, nCmdShow: i32) -> i32;
    fn GetWindowTextLengthW(hWnd: isize) -> i32;
    fn GetWindowTextW(hWnd: isize, lpString: *mut u16, nMaxCount: i32) -> i32;
    fn LoadImageW(
        hInst: isize,
        name: *const u16,
        type_: u32,
        cx: i32,
        cy: i32,
        fuLoad: u32,
    ) -> isize;
    fn SendMessageW(hWnd: isize, Msg: u32, wParam: usize, lParam: isize) -> isize;
    fn PostMessageW(hWnd: isize, Msg: u32, wParam: usize, lParam: isize) -> i32;
    fn IsIconic(hWnd: isize) -> i32;
    fn IsHungAppWindow(hWnd: isize) -> i32;
    fn SetWindowPos(
        hWnd: isize,
        hWndInsertAfter: isize,
        X: i32,
        Y: i32,
        cx: i32,
        cy: i32,
        uFlags: u32,
    ) -> i32;
    fn GetForegroundWindow() -> isize;
    fn GetWindowThreadProcessId(hWnd: isize, lpdwProcessId: *mut u32) -> u32;
    fn SendMessageTimeoutW(
        hWnd: isize,
        Msg: u32,
        wParam: usize,
        lParam: isize,
        fuFlags: u32,
        uTimeout: u32,
        lpdwResult: *mut usize,
    ) -> isize;
    fn GetIconInfo(hIcon: isize, piconinfo: *mut IconInfo) -> i32;
    fn DestroyIcon(hIcon: isize) -> i32;
    fn GetDC(hWnd: isize) -> isize;
    fn ReleaseDC(hWnd: isize, hDC: isize) -> i32;
}

#[cfg(target_os = "windows")]
#[link(name = "Shell32")]
extern "system" {
    fn ExtractIconExW(
        lpszFile: *const u16,
        nIconIndex: i32,
        phiconLarge: *mut isize,
        phiconSmall: *mut isize,
        nIcons: u32,
    ) -> u32;
}

#[cfg(target_os = "windows")]
#[link(name = "Gdi32")]
extern "system" {
    fn GetObjectW(h: isize, c: i32, pv: *mut std::ffi::c_void) -> i32;
    fn GetDIBits(
        hdc: isize,
        hbm: isize,
        start: u32,
        cLines: u32,
        lpvBits: *mut std::ffi::c_void,
        lpbmi: *mut BitmapInfoHeader,
        usage: u32,
    ) -> i32;
    fn DeleteObject(ho: isize) -> i32;
}

#[repr(C)]
struct IconInfo {
    f_icon: i32,
    x_hotspot: u32,
    y_hotspot: u32,
    hbm_mask: isize,
    hbm_color: isize,
}

#[repr(C)]
struct Bitmap {
    bm_type: i32,
    bm_width: i32,
    bm_height: i32,
    bm_width_bytes: i32,
    bm_planes: u16,
    bm_bits_pixel: u16,
    bm_bits: *mut std::ffi::c_void,
}

#[repr(C)]
struct BitmapInfoHeader {
    bi_size: u32,
    bi_width: i32,
    bi_height: i32,
    bi_planes: u16,
    bi_bit_count: u16,
    bi_compression: u32,
    bi_size_image: u32,
    bi_x_pels_per_meter: i32,
    bi_y_pels_per_meter: i32,
    bi_clr_used: u32,
    bi_clr_important: u32,
}

const WM_GETTEXT: u32 = 0x000D;
const SMTO_ABORTIFHUNG: u32 = 0x0002;

#[cfg(target_os = "windows")]
#[link(name = "Iphlpapi")]
extern "system" {
    fn GetExtendedTcpTable(
        pTcpTable: *mut std::ffi::c_void,
        pdwSize: *mut u32,
        bOrder: i32,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) -> u32;
    fn IcmpCreateFile() -> isize;
    fn IcmpCloseHandle(IcmpHandle: isize) -> i32;
    fn IcmpSendEcho(
        IcmpHandle: isize,
        DestinationAddress: u32,
        RequestData: *const std::ffi::c_void,
        RequestSize: u16,
        RequestOptions: *const std::ffi::c_void,
        ReplyBuffer: *mut std::ffi::c_void,
        ReplySize: u32,
        Timeout: u32,
    ) -> u32;
}

#[repr(C)]
struct IpOptionInformation {
    ttl: u8,
    tos: u8,
    flags: u8,
    options_size: u8,
    options_data: *mut u8,
}

#[repr(C)]
struct IcmpEchoReply {
    address: u32,
    status: u32,
    round_trip_time: u32,
    data_size: u16,
    reserved: u16,
    data: *mut std::ffi::c_void,
    options: IpOptionInformation,
}

#[cfg(target_os = "windows")]
#[link(name = "Advapi32")]
extern "system" {
    fn RegOpenKeyExW(
        hKey: isize,
        lpSubKey: *const u16,
        ulOptions: u32,
        samDesired: u32,
        phkResult: *mut isize,
    ) -> i32;
    fn RegQueryValueExW(
        hKey: isize,
        lpValueName: *const u16,
        lpReserved: *const u32,
        lpType: *mut u32,
        lpData: *mut u8,
        lpcbData: *mut u32,
    ) -> i32;
    fn RegSetValueExW(
        hKey: isize,
        lpValueName: *const u16,
        Reserved: u32,
        dwType: u32,
        lpData: *const u8,
        cbData: u32,
    ) -> i32;
    fn RegDeleteValueW(hKey: isize, lpValueName: *const u16) -> i32;
    fn RegEnumKeyExW(
        hKey: isize,
        dwIndex: u32,
        lpName: *mut u16,
        lpcchName: *mut u32,
        lpReserved: *const u32,
        lpClass: *mut u16,
        lpcchClass: *mut u32,
        lpftLastWriteTime: *mut u64,
    ) -> i32;
    fn RegCloseKey(hKey: isize) -> i32;
    fn StartTraceW(
        trace_handle: *mut u64,
        instance_name: *const u16,
        properties: *mut EventTraceProperties,
    ) -> u32;
    fn ControlTraceW(
        trace_handle: u64,
        instance_name: *const u16,
        properties: *mut EventTraceProperties,
        control_code: u32,
    ) -> u32;
    fn EnableTraceEx2(
        trace_handle: u64,
        provider_id: *const EtwGuid,
        control_code: u32,
        level: u8,
        match_any_keyword: u64,
        match_all_keyword: u64,
        timeout: u32,
        enable_parameters: *const std::ffi::c_void,
    ) -> u32;
    fn OpenTraceW(logfile: *mut EventTraceLogfileW) -> u64;
    fn ProcessTrace(
        handle_array: *const u64,
        handle_count: u32,
        start_time: *const i64,
        end_time: *const i64,
    ) -> u32;
    fn CloseTrace(trace_handle: u64) -> u32;
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct EtwGuid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

// Microsoft-Windows-DXGI: {CA11C036-0102-4A2D-A6AD-F03CFED5D3C9}
const DXGI_PROVIDER_GUID: EtwGuid = EtwGuid {
    data1: 0xCA11C036,
    data2: 0x0102,
    data3: 0x4A2D,
    data4: [0xA6, 0xAD, 0xF0, 0x3C, 0xFE, 0xD5, 0xD3, 0xC9],
};

// Microsoft-Windows-D3D9: {783ACA0A-790E-4D7F-8451-AA850511C6B9}
const D3D9_PROVIDER_GUID: EtwGuid = EtwGuid {
    data1: 0x783ACA0A,
    data2: 0x790E,
    data3: 0x4D7F,
    data4: [0x84, 0x51, 0xAA, 0x85, 0x05, 0x11, 0xC6, 0xB9],
};

#[repr(C)]
#[derive(Clone, Copy)]
struct WnodeHeader {
    buffer_size: u32,
    provider_id: u32,
    historical_context: u64,
    time_stamp: i64,
    guid: EtwGuid,
    client_context: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EventTraceProperties {
    wnode: WnodeHeader,
    buffer_size: u32,
    minimum_buffers: u32,
    maximum_buffers: u32,
    maximum_file_size: u32,
    log_file_mode: u32,
    flush_timer: u32,
    enable_flags: u32,
    age_limit: i32,
    number_of_buffers: u32,
    free_buffers: u32,
    events_lost: u32,
    buffers_written: u32,
    log_buffers_lost: u32,
    real_time_buffers_lost: u32,
    logger_thread_id: usize,
    log_file_name_offset: u32,
    logger_name_offset: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EventDescriptor {
    id: u16,
    version: u8,
    channel: u8,
    level: u8,
    opcode: u8,
    task: u16,
    keyword: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EventHeader {
    size: u16,
    header_type: u16,
    flags: u16,
    event_property: u16,
    thread_id: u32,
    process_id: u32,
    time_stamp: i64,
    provider_id: EtwGuid,
    event_descriptor: EventDescriptor,
    processor_time: u64,
    activity_id: EtwGuid,
}

#[repr(C)]
struct EventRecord {
    event_header: EventHeader,
    buffer_context: u32,
    extended_data_count: u16,
    user_data_length: u16,
    extended_data: usize,
    user_data: *const u8,
    user_context: *mut std::ffi::c_void,
}

#[repr(C)]
struct EventTraceLogfileW {
    log_file_name: *mut u16,
    logger_name: *mut u16,
    current_time: i64,
    buffers_read: u32,
    process_trace_mode: u32,
    current_event: [u8; 88],
    logfile_header: [u8; 280],
    buffer_callback: usize,
    buffer_size: u32,
    filled: u32,
    events_lost: u32,
    _pad1: u32,
    event_record_callback: Option<unsafe extern "system" fn(*mut EventRecord)>,
    is_kernel_trace: u32,
    _pad2: u32,
    context: *mut std::ffi::c_void,
}

const ETW_TICKS_PER_SEC: i64 = 10_000_000; // 100ns FILETIME 정규화 단위 (QPC 해상도 캡처)
const ETW_FPS_SESSION_NAME: &str = "CoreFlowFpsEtwSession";

struct SwapChainFrameHistory {
    timestamps: std::collections::VecDeque<i64>,
    last_seen: Instant,
}

#[derive(Clone, Copy, Default)]
struct PidFpsMetrics {
    fps: f32,
    frame_ms: f32,
    low_1pct_fps: f32,
    frame_count_1s: usize,
}

static ETW_FPS_MAP: std::sync::OnceLock<
    Mutex<std::collections::HashMap<(u32, u64), SwapChainFrameHistory>>,
> = std::sync::OnceLock::new();

fn get_etw_fps_map() -> &'static Mutex<std::collections::HashMap<(u32, u64), SwapChainFrameHistory>>
{
    ETW_FPS_MAP.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

unsafe extern "system" fn etw_present_record_callback(rec: *mut EventRecord) {
    if rec.is_null() {
        return;
    }
    let hdr = &(*rec).event_header;
    // DXGI Present_Start (Event ID 42, Opcode 1) 또는 D3D9 Present_Start (Event ID 1)
    let is_dxgi = hdr.provider_id == DXGI_PROVIDER_GUID && hdr.event_descriptor.id == 42;
    let is_d3d9 = hdr.provider_id == D3D9_PROVIDER_GUID && hdr.event_descriptor.id == 1;
    if !is_dxgi && !is_d3d9 {
        return;
    }

    let mut swapchain = 0u64;
    if is_dxgi {
        if (*rec).user_data_length >= 12 && !(*rec).user_data.is_null() {
            swapchain = std::ptr::read_unaligned((*rec).user_data as *const u64);
            let flags = std::ptr::read_unaligned((*rec).user_data.add(8) as *const u32);
            // DXGI_PRESENT_TEST (0x00000001) 호출은 실제 화면 출력이 아니므로 제외
            if (flags & 1) != 0 {
                return;
            }
        }
    } else if is_d3d9 && (*rec).user_data_length >= 8 && !(*rec).user_data.is_null() {
        swapchain = std::ptr::read_unaligned((*rec).user_data as *const u64);
    }

    let pid = hdr.process_id;
    if pid <= 4 {
        return;
    }
    let ts = hdr.time_stamp;
    let keep_window = ETW_TICKS_PER_SEC * 3; // 최근 3초 구간 프레임 타임스탬프 유지

    if let Ok(mut map) = get_etw_fps_map().lock() {
        if map.len() > 256 {
            map.retain(|_, v| v.last_seen.elapsed() < Duration::from_secs(8));
        }
        let entry = map
            .entry((pid, swapchain))
            .or_insert_with(|| SwapChainFrameHistory {
                timestamps: std::collections::VecDeque::with_capacity(512),
                last_seen: Instant::now(),
            });
        if let Some(&last_ts) = entry.timestamps.back() {
            if ts > last_ts {
                entry.timestamps.push_back(ts);
            } else if ts < last_ts {
                // 멀티코어 환경에서 CPU 코어별 ETW 버퍼 플러시 순서 차이로 타임스탬프가 역전된 경우에도 유실 없이 정렬 삽입
                if let Err(pos) = entry.timestamps.binary_search(&ts) {
                    entry.timestamps.insert(pos, ts);
                }
            }
        } else {
            entry.timestamps.push_back(ts);
        }
        entry.last_seen = Instant::now();
        if let Some(&newest) = entry.timestamps.back() {
            let cutoff = newest - keep_window;
            while entry.timestamps.len() > 1500
                || entry.timestamps.front().map_or(false, |&t| t < cutoff)
            {
                entry.timestamps.pop_front();
            }
        }
    }
}

fn compute_swapchain_fps(hist: &SwapChainFrameHistory) -> Option<PidFpsMetrics> {
    let idle_secs = hist.last_seen.elapsed().as_secs_f64();
    // Windows ETW 실시간 버퍼는 flush_timer=1초 주기로 코어별 버퍼를 병합 전달하므로 최대 2.8초까지 활성 유지
    if idle_secs > 2.8 || hist.timestamps.len() < 2 {
        return None;
    }
    let last_ts = *hist.timestamps.back()?;
    let window_1s_start = last_ts - ETW_TICKS_PER_SEC;

    let first_in_1s_idx = hist
        .timestamps
        .iter()
        .position(|&t| t >= window_1s_start)
        .unwrap_or(0);

    let recent_len = hist.timestamps.len() - first_in_1s_idx;
    if recent_len < 2 {
        return None;
    }

    let first_ts_in_1s = hist.timestamps[first_in_1s_idx];
    // 최근 1초 윈도우 시작점 근처에서 연속 렌더링 중인지, 아니면 긴 멈춤 후 일부만 렌더링된 것인지 판별
    let (interval_count, span_secs) = if first_in_1s_idx > 0
        && (first_ts_in_1s - window_1s_start) > (ETW_TICKS_PER_SEC / 4)
    {
        // 윈도우 초반에 250ms 이상의 긴 프레임 멈춤 공백이 있었던 경우 1초 전체 폭으로 계산
        (recent_len as f64, 1.0f64)
    } else {
        // 연속 렌더링 중인 게임: 실제 첫 프레임과 마지막 프레임 사이의 순수 하드웨어 QPC 간격으로 나눔 (ETW 버퍼 플러시 지연과 무관하게 100% 정확한 FPS 산출)
        let raw_span = (last_ts - first_ts_in_1s) as f64 / (ETW_TICKS_PER_SEC as f64);
        ((recent_len - 1) as f64, raw_span)
    };

    if span_secs < 0.05 {
        return None;
    }

    let fps = (interval_count / span_secs) as f32;
    if fps < 1.0 || fps > 2000.0 {
        return None;
    }
    let frame_ms = 1000.0 / fps;

    // 최근 3초간의 개별 프레임 간격(dt_ms) 하위 1% 평균으로 정확한 1% Low FPS 산출
    let mut deltas_ms: Vec<f64> = Vec::with_capacity(hist.timestamps.len());
    for i in 1..hist.timestamps.len() {
        let dt_ms = ((hist.timestamps[i] - hist.timestamps[i - 1]) as f64 * 1000.0)
            / (ETW_TICKS_PER_SEC as f64);
        if dt_ms > 0.1 && dt_ms < 500.0 {
            deltas_ms.push(dt_ms);
        }
    }
    let low_1pct_fps = if !deltas_ms.is_empty() {
        deltas_ms.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
        let slow_n = ((deltas_ms.len() as f64 * 0.01).ceil() as usize).max(1);
        let avg_slow_ms = deltas_ms.iter().take(slow_n).sum::<f64>() / (slow_n as f64);
        if avg_slow_ms > 0.0 {
            ((1000.0 / avg_slow_ms) as f32).min(fps)
        } else {
            fps
        }
    } else {
        fps
    };

    Some(PidFpsMetrics {
        fps,
        frame_ms,
        low_1pct_fps,
        frame_count_1s: recent_len,
    })
}

/// 현재 DXGI / D3D9 SwapChain Present를 수행 중인 모든 프로세스의 실시간 하드웨어 FPS 맵 조회
fn query_all_active_pid_fps() -> std::collections::HashMap<u32, PidFpsMetrics> {
    let mut result = std::collections::HashMap::new();
    let Ok(mut map) = get_etw_fps_map().lock() else {
        return result;
    };
    map.retain(|_, v| v.last_seen.elapsed() < Duration::from_secs(5));
    for (&(pid, _sc), hist) in map.iter() {
        if let Some(metrics) = compute_swapchain_fps(hist) {
            let replace = match result.get(&pid) {
                None => true,
                Some(prev) => metrics.frame_count_1s > prev.frame_count_1s,
            };
            if replace {
                result.insert(pid, metrics);
            }
        }
    }
    result
}

#[cfg(target_os = "windows")]
fn stop_fps_etw_session() {
    let session_name = to_wide(ETW_FPS_SESSION_NAME);
    let total_size = std::mem::size_of::<EventTraceProperties>() + session_name.len() * 2 + 64;
    let mut buf = vec![0u64; (total_size + 7) / 8];
    let props_ptr = buf.as_mut_ptr() as *mut EventTraceProperties;
    unsafe {
        (*props_ptr).wnode.buffer_size = (buf.len() * 8) as u32;
        (*props_ptr).logger_name_offset = std::mem::size_of::<EventTraceProperties>() as u32;
        let _ = ControlTraceW(0, session_name.as_ptr(), props_ptr, 1);
    }
}

#[cfg(not(target_os = "windows"))]
fn stop_fps_etw_session() {}

/// NVIDIA 오버레이 / PresentMon과 동일한 Windows ETW (DXGI + D3D9 Present) 하드웨어 프레임 측정 스레드
#[cfg(target_os = "windows")]
fn spawn_fps_etw_monitor() {
    thread::spawn(|| {
        let session_name = to_wide(ETW_FPS_SESSION_NAME);
        let total_size = std::mem::size_of::<EventTraceProperties>() + session_name.len() * 2 + 64;
        let mut tried_group_add = false;

        loop {
            let mut buf = vec![0u64; (total_size + 7) / 8];
            let props_ptr = buf.as_mut_ptr() as *mut EventTraceProperties;

            unsafe {
                // 이전 잔여 세션 정리
                (*props_ptr).wnode.buffer_size = (buf.len() * 8) as u32;
                (*props_ptr).logger_name_offset =
                    std::mem::size_of::<EventTraceProperties>() as u32;
                let _ = ControlTraceW(0, session_name.as_ptr(), props_ptr, 1);

                std::ptr::write_bytes(buf.as_mut_ptr(), 0, buf.len());
                (*props_ptr).wnode.buffer_size = (buf.len() * 8) as u32;
                (*props_ptr).wnode.flags = 0x00020000; // WNODE_FLAG_TRACED_GUID
                (*props_ptr).wnode.client_context = 1; // QPC 고정밀 타임스탬프 캡처
                (*props_ptr).log_file_mode = 0x00000100; // EVENT_TRACE_REAL_TIME_MODE
                (*props_ptr).buffer_size = 16;
                (*props_ptr).minimum_buffers = 4;
                (*props_ptr).maximum_buffers = 32;
                (*props_ptr).flush_timer = 1;
                (*props_ptr).logger_name_offset =
                    std::mem::size_of::<EventTraceProperties>() as u32;

                let mut session_handle: u64 = 0;
                let status = StartTraceW(&mut session_handle, session_name.as_ptr(), props_ptr);
                if status != 0 {
                    // ERROR_ACCESS_DENIED (5)인 경우 Performance Log Users 그룹(S-1-5-32-559) 등록 1회 시도
                    if status == 5 && !tried_group_add {
                        tried_group_add = true;
                        if let Ok(user) = std::env::var("USERNAME") {
                            let _ = Command::new("net")
                                .args(["localgroup", "*S-1-5-32-559", &user, "/add"])
                                .no_window()
                                .status();
                        }
                    }
                    thread::sleep(Duration::from_secs(10));
                    continue;
                }

                let _ = EnableTraceEx2(
                    session_handle,
                    &DXGI_PROVIDER_GUID,
                    1,
                    4,
                    0,
                    0,
                    0,
                    std::ptr::null(),
                );
                let _ = EnableTraceEx2(
                    session_handle,
                    &D3D9_PROVIDER_GUID,
                    1,
                    4,
                    0,
                    0,
                    0,
                    std::ptr::null(),
                );

                let mut logfile: EventTraceLogfileW = std::mem::MaybeUninit::zeroed().assume_init();
                let mut sname_mut = session_name.clone();
                logfile.logger_name = sname_mut.as_mut_ptr();
                // PROCESS_TRACE_MODE_REAL_TIME (0x00000100) | PROCESS_TRACE_MODE_EVENT_RECORD (0x10000000)
                logfile.process_trace_mode = 0x00000100 | 0x10000000;
                logfile.event_record_callback = Some(etw_present_record_callback);

                let trace_handle = OpenTraceW(&mut logfile);
                if trace_handle == u64::MAX || trace_handle == 0xFFFFFFFF {
                    let _ = ControlTraceW(session_handle, std::ptr::null(), props_ptr, 1);
                    thread::sleep(Duration::from_secs(5));
                    continue;
                }

                // ProcessTrace는 세션이 닫힐 때까지 블로킹하며 실시간 Present 이벤트를 수신
                let _ = ProcessTrace(&trace_handle, 1, std::ptr::null(), std::ptr::null());
                let _ = CloseTrace(trace_handle);
                let _ = ControlTraceW(session_handle, std::ptr::null(), props_ptr, 1);
            }
            thread::sleep(Duration::from_secs(3));
        }
    });
}

#[cfg(not(target_os = "windows"))]
fn spawn_fps_etw_monitor() {}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

const DEFAULT_PROC_ICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#7a869a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="3" fill="#7a869a" fill-opacity="0.14"/><rect x="9" y="9" width="6" height="6" rx="1"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/></svg>"##;

static EXE_PATH_MAP: std::sync::OnceLock<Mutex<std::collections::HashMap<String, String>>> =
    std::sync::OnceLock::new();
static ICON_CACHE: std::sync::OnceLock<Mutex<std::collections::HashMap<String, Option<Vec<u8>>>>> =
    std::sync::OnceLock::new();

fn get_exe_path_map() -> &'static Mutex<std::collections::HashMap<String, String>> {
    EXE_PATH_MAP.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn get_icon_cache() -> &'static Mutex<std::collections::HashMap<String, Option<Vec<u8>>>> {
    ICON_CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

#[cfg(target_os = "windows")]
unsafe fn hicon_to_ico_bytes(hicon: isize) -> Option<Vec<u8>> {
    if hicon == 0 {
        return None;
    }
    let mut ii: IconInfo = std::mem::zeroed();
    if GetIconInfo(hicon, &mut ii) == 0 {
        return None;
    }
    if ii.hbm_color == 0 {
        if ii.hbm_mask != 0 {
            DeleteObject(ii.hbm_mask);
        }
        return None;
    }

    let mut bm: Bitmap = std::mem::zeroed();
    let got_obj = GetObjectW(
        ii.hbm_color,
        std::mem::size_of::<Bitmap>() as i32,
        &mut bm as *mut _ as *mut std::ffi::c_void,
    );
    let w = bm.bm_width;
    let h = bm.bm_height;
    if got_obj == 0 || w <= 0 || h <= 0 || w > 256 || h > 256 {
        DeleteObject(ii.hbm_color);
        if ii.hbm_mask != 0 {
            DeleteObject(ii.hbm_mask);
        }
        return None;
    }

    let hdc = GetDC(0);
    if hdc == 0 {
        DeleteObject(ii.hbm_color);
        if ii.hbm_mask != 0 {
            DeleteObject(ii.hbm_mask);
        }
        return None;
    }

    let mut bmi = BitmapInfoHeader {
        bi_size: std::mem::size_of::<BitmapInfoHeader>() as u32,
        bi_width: w,
        bi_height: h,
        bi_planes: 1,
        bi_bit_count: 32,
        bi_compression: 0,
        bi_size_image: (w * h * 4) as u32,
        bi_x_pels_per_meter: 0,
        bi_y_pels_per_meter: 0,
        bi_clr_used: 0,
        bi_clr_important: 0,
    };

    let pixel_count = (w * h) as usize;
    let mut color_bytes = vec![0u8; pixel_count * 4];
    let lines = GetDIBits(
        hdc,
        ii.hbm_color,
        0,
        h as u32,
        color_bytes.as_mut_ptr() as *mut std::ffi::c_void,
        &mut bmi,
        0,
    );

    if lines == 0 {
        ReleaseDC(0, hdc);
        DeleteObject(ii.hbm_color);
        if ii.hbm_mask != 0 {
            DeleteObject(ii.hbm_mask);
        }
        return None;
    }

    let has_alpha = color_bytes.chunks_exact(4).any(|px| px[3] != 0);
    if !has_alpha && ii.hbm_mask != 0 {
        let mut mask_bmi = BitmapInfoHeader {
            bi_size: std::mem::size_of::<BitmapInfoHeader>() as u32,
            bi_width: w,
            bi_height: h,
            bi_planes: 1,
            bi_bit_count: 32,
            bi_compression: 0,
            bi_size_image: (w * h * 4) as u32,
            bi_x_pels_per_meter: 0,
            bi_y_pels_per_meter: 0,
            bi_clr_used: 0,
            bi_clr_important: 0,
        };
        let mut mask_bytes = vec![0u8; pixel_count * 4];
        let mlines = GetDIBits(
            hdc,
            ii.hbm_mask,
            0,
            h as u32,
            mask_bytes.as_mut_ptr() as *mut std::ffi::c_void,
            &mut mask_bmi,
            0,
        );
        if mlines != 0 {
            for (c_px, m_px) in color_bytes
                .chunks_exact_mut(4)
                .zip(mask_bytes.chunks_exact(4))
            {
                c_px[3] = if m_px[0] == 0 { 255 } else { 0 };
            }
        } else {
            for c_px in color_bytes.chunks_exact_mut(4) {
                c_px[3] = 255;
            }
        }
    } else if !has_alpha {
        for c_px in color_bytes.chunks_exact_mut(4) {
            c_px[3] = 255;
        }
    }

    ReleaseDC(0, hdc);
    DeleteObject(ii.hbm_color);
    if ii.hbm_mask != 0 {
        DeleteObject(ii.hbm_mask);
    }

    let and_row_bytes = (((w + 31) / 32) * 4) as usize;
    let and_mask_size = and_row_bytes * (h as usize);
    let dib_header_size = 40usize;
    let image_data_size = dib_header_size + color_bytes.len() + and_mask_size;

    let mut ico = Vec::with_capacity(22 + image_data_size);
    ico.extend_from_slice(&[0, 0, 1, 0, 1, 0]);
    ico.push(if w >= 256 { 0 } else { w as u8 });
    ico.push(if h >= 256 { 0 } else { h as u8 });
    ico.push(0);
    ico.push(0);
    ico.extend_from_slice(&1u16.to_le_bytes());
    ico.extend_from_slice(&32u16.to_le_bytes());
    ico.extend_from_slice(&(image_data_size as u32).to_le_bytes());
    ico.extend_from_slice(&22u32.to_le_bytes());

    ico.extend_from_slice(&40u32.to_le_bytes());
    ico.extend_from_slice(&w.to_le_bytes());
    ico.extend_from_slice(&(h * 2).to_le_bytes());
    ico.extend_from_slice(&1u16.to_le_bytes());
    ico.extend_from_slice(&32u16.to_le_bytes());
    ico.extend_from_slice(&0u32.to_le_bytes());
    ico.extend_from_slice(&((color_bytes.len() + and_mask_size) as u32).to_le_bytes());
    ico.extend_from_slice(&0i32.to_le_bytes());
    ico.extend_from_slice(&0i32.to_le_bytes());
    ico.extend_from_slice(&0u32.to_le_bytes());
    ico.extend_from_slice(&0u32.to_le_bytes());

    ico.extend_from_slice(&color_bytes);
    ico.resize(ico.len() + and_mask_size, 0u8);

    Some(ico)
}

#[cfg(target_os = "windows")]
fn extract_exe_icon_ico(exe_path: &str) -> Option<Vec<u8>> {
    if exe_path.is_empty() || !std::path::Path::new(exe_path).exists() {
        return None;
    }
    let path_w = to_wide(exe_path);
    unsafe {
        let mut h_large: isize = 0;
        let mut h_small: isize = 0;
        let _ = ExtractIconExW(path_w.as_ptr(), 0, &mut h_large, &mut h_small, 1);
        let target_hicon = if h_large != 0 {
            if h_small != 0 {
                DestroyIcon(h_small);
            }
            h_large
        } else if h_small != 0 {
            h_small
        } else {
            0
        };

        if target_hicon != 0 {
            let res = hicon_to_ico_bytes(target_hicon);
            DestroyIcon(target_hicon);
            return res;
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn extract_exe_icon_ico(_exe_path: &str) -> Option<Vec<u8>> {
    None
}

fn resolve_and_get_proc_icon(exe_name: &str) -> Option<Vec<u8>> {
    let key = exe_name.trim().to_lowercase();
    if key.is_empty() {
        return None;
    }
    if key == "coreflow.exe" || key == "coreflow" {
        return Some(APP_ICON_ICO.to_vec());
    }

    if let Ok(cache) = get_icon_cache().lock() {
        if let Some(cached) = cache.get(&key) {
            return cached.clone();
        }
    }

    let mut candidate_path = get_exe_path_map()
        .lock()
        .ok()
        .and_then(|m| m.get(&key).cloned());

    if candidate_path.is_none() {
        let sys32 = format!(r"C:\Windows\System32\{key}");
        let win = format!(r"C:\Windows\{key}");
        let syswow = format!(r"C:\Windows\SysWOW64\{key}");
        if std::path::Path::new(&sys32).exists() {
            candidate_path = Some(sys32);
        } else if std::path::Path::new(&win).exists() {
            candidate_path = Some(win);
        } else if std::path::Path::new(&syswow).exists() {
            candidate_path = Some(syswow);
        }
    }

    if let Some(full_path) = candidate_path {
        let extracted = extract_exe_icon_ico(&full_path);
        if let Ok(mut cache) = get_icon_cache().lock() {
            cache.insert(key, extracted.clone());
        }
        extracted
    } else {
        None
    }
}

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const GITHUB_REPO: &str = "neverloselkb/coreFlow";

fn parse_semver(ver: &str) -> (u32, u32, u32) {
    let cleaned = ver.trim().trim_start_matches(|c: char| !c.is_ascii_digit());
    let mut parts = cleaned.split(|c: char| !c.is_ascii_digit());
    let major = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor, patch)
}

fn is_newer_version(current: &str, latest: &str) -> bool {
    parse_semver(latest) > parse_semver(current)
}

fn extract_json_str_field(json: &str, field: &str) -> Option<String> {
    let pat = format!("\"{}\"", field);
    let idx = json.find(&pat)?;
    let rest = &json[idx + pat.len()..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let mut out = String::new();
    let mut chars = after_colon[1..].chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(esc) = chars.next() {
                match esc {
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'u' => {
                        let hex: String = chars.by_ref().take(4).collect();
                        if let Ok(code) = u32::from_str_radix(&hex, 16) {
                            if let Some(ch) = char::from_u32(code) {
                                out.push(ch);
                            }
                        }
                    }
                    other => out.push(other),
                }
            }
        } else if c == '"' {
            return Some(out);
        } else {
            out.push(c);
        }
    }
    None
}

/// GitHub Releases API (`neverloselkb/coreFlow`)를 조회하여 최신 버전 및 다운로드 URL 확인
fn check_github_update() -> String {
    let api_url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");
    let curl_bin = if cfg!(windows) { "curl.exe" } else { "curl" };
    let out = Command::new(curl_bin)
        .args([
            "-sL",
            "--max-time",
            "8",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "User-Agent: CoreFlow-Updater",
            &api_url,
        ])
        .no_window()
        .output();

    let Ok(output) = out else {
        return format!(
            r#"{{"ok":false,"current_version":"{}","error":"네트워크 요청 실행에 실패했습니다."}}"#,
            APP_VERSION
        );
    };

    let body = String::from_utf8_lossy(&output.stdout);
    let Some(tag_raw) = extract_json_str_field(&body, "tag_name") else {
        let release_page = format!("https://github.com/{GITHUB_REPO}/releases");
        return format!(
            r#"{{"ok":true,"has_update":false,"current_version":"{}","latest_version":"{}","download_url":"","html_url":"{}","notes":"아직 GitHub에 배포된 공식 Release 태그가 없습니다. 현재 최신 버전을 사용 중입니다."}}"#,
            APP_VERSION, APP_VERSION, release_page
        );
    };

    let latest_clean = tag_raw.trim().trim_start_matches('v').trim_start_matches('V');
    let has_update = is_newer_version(APP_VERSION, latest_clean);
    let notes = extract_json_str_field(&body, "body").unwrap_or_default();
    let html_url = extract_json_str_field(&body, "html_url")
        .unwrap_or_else(|| format!("https://github.com/{GITHUB_REPO}/releases"));

    // 플랫폼별 업데이트 바이너리/패키지 다운로드 URL 추출
    #[cfg(target_os = "windows")]
    let target_ext = "coreflow_setup.exe";
    #[cfg(target_os = "macos")]
    let target_ext = ".zip";
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    let target_ext = ".tar.gz";

    let mut download_url = String::new();
    let mut search_slice = body.as_ref();
    while let Some(pos) = search_slice.find("\"browser_download_url\"") {
        let sub = &search_slice[pos..];
        if let Some(u) = extract_json_str_field(sub, "browser_download_url") {
            if u.to_ascii_lowercase().ends_with(target_ext) {
                download_url = u;
                break;
            }
        }
        search_slice = &search_slice[pos + 22..];
    }
    if download_url.is_empty() {
        #[cfg(target_os = "windows")]
        {
            download_url = format!(
                "https://github.com/{GITHUB_REPO}/releases/download/{}/CoreFlow_Setup.exe",
                tag_raw.trim()
            );
        }
        #[cfg(target_os = "macos")]
        {
            download_url = format!(
                "https://github.com/{GITHUB_REPO}/releases/download/{}/CoreFlow-macOS-universal.zip",
                tag_raw.trim()
            );
        }
    }

    format!(
        r#"{{"ok":true,"has_update":{},"current_version":"{}","latest_version":"{}","tag_name":"{}","download_url":"{}","html_url":"{}","notes":"{}"}}"#,
        has_update,
        json_escape(APP_VERSION),
        json_escape(latest_clean),
        json_escape(tag_raw.trim()),
        json_escape(&download_url),
        json_escape(&html_url),
        json_escape(&notes)
    )
}

#[cfg(target_os = "windows")]
/// GitHub Release에서 최신 `CoreFlow_Setup.exe`를 다운로드하여 무인 업데이트(`--silent-update`) 실행
fn perform_github_self_update(download_url: &str, state: &Arc<Mutex<SharedState>>) -> String {
    if !download_url.starts_with("https://github.com/neverloselkb/coreFlow/")
        && !download_url.starts_with("https://objects.githubusercontent.com/")
    {
        return r#"{"ok":false,"error":"허용되지 않은 업데이트 다운로드 경로입니다."}"#.to_string();
    }

    let tmp_installer = std::env::temp_dir().join("CoreFlow_Setup_Update.exe");
    let _ = std::fs::remove_file(&tmp_installer);

    let status = Command::new("curl.exe")
        .args([
            "-sL",
            "--fail",
            "--max-time",
            "120",
            "-H",
            "User-Agent: CoreFlow-Updater",
            "-o",
        ])
        .arg(&tmp_installer)
        .arg(download_url)
        .no_window()
        .status();

    let downloaded_ok = status.map(|s| s.success()).unwrap_or(false)
        && std::fs::metadata(&tmp_installer)
            .map(|m| m.len() > 500_000)
            .unwrap_or(false);

    if !downloaded_ok {
        return r#"{"ok":false,"error":"GitHub Releases에서 CoreFlow_Setup.exe 설치 파일을 다운로드하지 못했습니다. Release에 CoreFlow_Setup.exe 파일이 첨부되어 있는지 확인해 주세요."}"#.to_string();
    }

    let current_install_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_string_lossy().to_string()))
        .unwrap_or_else(|| r"C:\Program Files\CoreFlow".to_string());

    if let Ok(guard) = state.lock() {
        save_game_sessions(&guard.game_sessions);
    }

    let spawn_res = Command::new(&tmp_installer)
        .args(["--silent-update", "--dir", &current_install_dir])
        .no_window()
        .spawn();

    if spawn_res.is_err() {
        return r#"{"ok":false,"error":"업데이트 설치 마법사 실행에 실패했습니다."}"#.to_string();
    }

    // 350ms 후 현재 UI 창을 닫고 프로세스를 종료하여 업데이트 설치기가 파일을 교체할 수 있도록 함
    thread::spawn(|| {
        thread::sleep(Duration::from_millis(350));
        close_stale_app_window();
        std::process::exit(0);
    });

    r#"{"ok":true}"#.to_string()
}

#[cfg(target_os = "macos")]
/// GitHub Release에서 최신 `CoreFlow-macOS-universal.zip`을 다운로드하여 앱 번들 교체 및 자동 재시작
fn perform_github_self_update(download_url: &str, state: &Arc<Mutex<SharedState>>) -> String {
    if !download_url.starts_with("https://github.com/neverloselkb/coreFlow/")
        && !download_url.starts_with("https://objects.githubusercontent.com/")
    {
        return r#"{"ok":false,"error":"허용되지 않은 업데이트 다운로드 경로입니다."}"#.to_string();
    }

    let tmp_zip = std::env::temp_dir().join("CoreFlow_Update.zip");
    let _ = std::fs::remove_file(&tmp_zip);
    let tmp_extract_dir = std::env::temp_dir().join("CoreFlow_Update_Extracted");
    let _ = std::fs::remove_dir_all(&tmp_extract_dir);
    let _ = std::fs::create_dir_all(&tmp_extract_dir);

    let status = Command::new("curl")
        .args([
            "-sL",
            "--fail",
            "--max-time",
            "180",
            "-H",
            "User-Agent: CoreFlow-Updater",
            "-o",
        ])
        .arg(&tmp_zip)
        .arg(download_url)
        .status();

    let downloaded_ok = status.map(|s| s.success()).unwrap_or(false)
        && std::fs::metadata(&tmp_zip)
            .map(|m| m.len() > 100_000)
            .unwrap_or(false);

    if !downloaded_ok {
        return r#"{"ok":false,"error":"GitHub Releases에서 CoreFlow 업데이트 패키지를 다운로드하지 못했습니다."}"#.to_string();
    }

    let unzip_status = Command::new("unzip")
        .args(["-q", "-o"])
        .arg(&tmp_zip)
        .args(["-d"])
        .arg(&tmp_extract_dir)
        .status();

    if !unzip_status.map(|s| s.success()).unwrap_or(false) {
        return r#"{"ok":false,"error":"업데이트 압축 파일(ZIP)의 압축 해제에 실패했습니다."}"#.to_string();
    }

    let extracted_app = tmp_extract_dir.join("CoreFlow.app");
    if !extracted_app.exists() {
        return r#"{"ok":false,"error":"압축 파일 내에서 CoreFlow.app 번들을 찾을 수 없습니다."}"#.to_string();
    }

    // 현재 실행 중인 .app 번들 경로 감지 (없으면 /Applications/CoreFlow.app 기본값)
    let current_exe = std::env::current_exe().unwrap_or_default();
    let current_app_bundle = current_exe
        .parent() // Contents/MacOS
        .and_then(|p| p.parent()) // Contents
        .and_then(|p| p.parent()) // CoreFlow.app
        .filter(|p| p.extension().map(|e| e == "app").unwrap_or(false))
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("/Applications/CoreFlow.app"));

    let target_app_str = current_app_bundle.to_string_lossy().to_string();
    let extracted_app_str = extracted_app.to_string_lossy().to_string();

    if let Ok(guard) = state.lock() {
        save_game_sessions(&guard.game_sessions);
    }

    // 백그라운드 쉘 스크립트 실행: 0.5초 대기 -> 기존 .app 삭제 -> 새 .app 복사 -> 격리 속성 해제 -> 앱 재실행
    let update_script = format!(
        r#"sleep 0.5; rm -rf "{}" && cp -R "{}" "{}" && xattr -dr com.apple.quarantine "{}" 2>/dev/null; open "{}""#,
        target_app_str, extracted_app_str, target_app_str, target_app_str, target_app_str
    );

    let spawn_res = Command::new("sh")
        .args(["-c", &update_script])
        .spawn();

    if spawn_res.is_err() {
        return r#"{"ok":false,"error":"macOS 업데이트 갱신 스크립트 실행에 실패했습니다."}"#.to_string();
    }

    // 350ms 후 현재 프로세스를 종료하여 스크립트가 앱을 교체하고 다시 열 수 있도록 함
    thread::spawn(|| {
        thread::sleep(Duration::from_millis(350));
        std::process::exit(0);
    });

    r#"{"ok":true}"#.to_string()
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn perform_github_self_update(_download_url: &str, _state: &Arc<Mutex<SharedState>>) -> String {
    r#"{"ok":false,"error":"지원되지 않는 운영체제입니다."}"#.to_string()
}

#[cfg(target_os = "windows")]
/// 현재 사용자가 조작 중인 Windows 전면(포그라운드) 활성 창의 프로세스 ID와 창 제목 반환 (타임아웃 적용으로 교착 방지)
fn get_foreground_window_info() -> Option<(u32, String)> {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd == 0 {
            return None;
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if pid == 0 {
            return None;
        }
        // 대상 창이 멈춤(응답없음) 상태면 텍스트 조회를 건너뛰고 PID만 즉시 반환
        if IsHungAppWindow(hwnd) != 0 {
            return Some((pid, String::new()));
        }

        let mut buf = [0u16; 512];
        let mut result_len: usize = 0;
        let ret = SendMessageTimeoutW(
            hwnd,
            WM_GETTEXT,
            buf.len(),
            buf.as_mut_ptr() as isize,
            SMTO_ABORTIFHUNG,
            120, // 120ms 초과 시 즉시 포기하여 교착(Deadlock) 원천 차단
            &mut result_len,
        );

        let title = if ret != 0 && result_len > 0 {
            let actual = result_len.min(buf.len() - 1);
            String::from_utf16_lossy(&buf[..actual]).trim().to_string()
        } else {
            String::new()
        };
        Some((pid, title))
    }
}

#[cfg(not(target_os = "windows"))]
fn get_foreground_window_info() -> Option<(u32, String)> {
    None
}

/// 외부 프로세스(reg.exe) 실행 없이 순수 Win32 API로 DWORD 레지스트리 값 읽기
#[cfg(target_os = "windows")]
fn reg_read_dword(root: isize, subkey: &str, value_name: &str) -> Option<u32> {
    let subkey_w = to_wide(subkey);
    let val_w = to_wide(value_name);
    let mut hkey: isize = 0;
    let status = unsafe { RegOpenKeyExW(root, subkey_w.as_ptr(), 0, KEY_READ, &mut hkey) };
    if status != 0 {
        return None;
    }
    let mut dw_type: u32 = 0;
    let mut data = [0u8; 4];
    let mut size: u32 = 4;
    let q_status = unsafe {
        RegQueryValueExW(
            hkey,
            val_w.as_ptr(),
            std::ptr::null(),
            &mut dw_type,
            data.as_mut_ptr(),
            &mut size,
        )
    };
    unsafe {
        RegCloseKey(hkey);
    }
    if q_status == 0 && dw_type == REG_DWORD && size == 4 {
        Some(u32::from_ne_bytes(data))
    } else {
        None
    }
}

#[cfg(not(target_os = "windows"))]
fn reg_read_dword(_root: isize, _subkey: &str, _value_name: &str) -> Option<u32> {
    None
}

/// 외부 프로세스(reg.exe) 실행 없이 순수 Win32 API로 문자열(REG_SZ) 레지스트리 값 읽기
#[cfg(target_os = "windows")]
fn reg_read_string(root: isize, subkey: &str, value_name: &str) -> Option<String> {
    let subkey_w = to_wide(subkey);
    let val_w = to_wide(value_name);
    let mut hkey: isize = 0;
    let status = unsafe { RegOpenKeyExW(root, subkey_w.as_ptr(), 0, KEY_READ, &mut hkey) };
    if status != 0 {
        return None;
    }
    let mut dw_type: u32 = 0;
    let mut buf = vec![0u16; 512];
    let mut size_bytes: u32 = (buf.len() * 2) as u32;
    let q_status = unsafe {
        RegQueryValueExW(
            hkey,
            val_w.as_ptr(),
            std::ptr::null(),
            &mut dw_type,
            buf.as_mut_ptr() as *mut u8,
            &mut size_bytes,
        )
    };
    unsafe {
        RegCloseKey(hkey);
    }
    if q_status == 0 && (dw_type == REG_SZ || dw_type == 2) && size_bytes >= 2 {
        let len_u16 = (size_bytes as usize) / 2;
        let slice = &buf[..len_u16];
        let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
        let s = String::from_utf16_lossy(&slice[..end]).trim().to_string();
        if !s.is_empty() {
            return Some(s);
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn reg_read_string(_root: isize, _subkey: &str, _value_name: &str) -> Option<String> {
    None
}

#[cfg(target_os = "windows")]
fn reg_write_string(root: isize, subkey: &str, value_name: &str, data: &str) -> bool {
    let subkey_w = to_wide(subkey);
    let val_w = to_wide(value_name);
    let data_w = to_wide(data);
    let mut hkey: isize = 0;
    let status = unsafe { RegOpenKeyExW(root, subkey_w.as_ptr(), 0, KEY_SET_VALUE, &mut hkey) };
    if status != 0 {
        return false;
    }
    let set_status = unsafe {
        RegSetValueExW(
            hkey,
            val_w.as_ptr(),
            0,
            REG_SZ,
            data_w.as_ptr() as *const u8,
            (data_w.len() * 2) as u32,
        )
    };
    unsafe {
        RegCloseKey(hkey);
    }
    set_status == 0
}

#[cfg(not(target_os = "windows"))]
fn reg_write_string(_root: isize, _subkey: &str, _value_name: &str, _data: &str) -> bool {
    false
}

#[cfg(target_os = "windows")]
fn reg_delete_value(root: isize, subkey: &str, value_name: &str) -> bool {
    let subkey_w = to_wide(subkey);
    let val_w = to_wide(value_name);
    let mut hkey: isize = 0;
    let status = unsafe { RegOpenKeyExW(root, subkey_w.as_ptr(), 0, KEY_SET_VALUE, &mut hkey) };
    if status != 0 {
        return false;
    }
    let del_status = unsafe { RegDeleteValueW(hkey, val_w.as_ptr()) };
    unsafe {
        RegCloseKey(hkey);
    }
    del_status == 0
}

#[cfg(not(target_os = "windows"))]
fn reg_delete_value(_root: isize, _subkey: &str, _value_name: &str) -> bool {
    false
}

#[cfg(target_os = "windows")]
fn reg_find_subkey_string(root: isize, parent_key: &str, value_name: &str) -> Option<String> {
    let parent_w = to_wide(parent_key);
    let mut hkey: isize = 0;
    let status = unsafe { RegOpenKeyExW(root, parent_w.as_ptr(), 0, KEY_READ, &mut hkey) };
    if status != 0 {
        return None;
    }
    let mut idx = 0u32;
    let mut found = None;
    loop {
        let mut name_buf = [0u16; 260];
        let mut name_len = name_buf.len() as u32;
        let enum_status = unsafe {
            RegEnumKeyExW(
                hkey,
                idx,
                name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if enum_status != 0 {
            break;
        }
        let sub_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        let child_path = format!(r"{parent_key}\{sub_name}");
        if let Some(val) = reg_read_string(root, &child_path, value_name) {
            found = Some(val);
            break;
        }
        idx += 1;
        if idx > 64 {
            break;
        }
    }
    unsafe {
        RegCloseKey(hkey);
    }
    found
}

#[cfg(not(target_os = "windows"))]
fn reg_find_subkey_string(_root: isize, _parent_key: &str, _value_name: &str) -> Option<String> {
    None
}

fn generate_session_token() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id() as u128;
    let stack_addr = (&nanos as *const u128 as usize) as u128;
    let mixed1 = nanos ^ (pid.rotate_left(32)) ^ (stack_addr.rotate_left(17));
    let mixed2 = nanos.wrapping_mul(0x9E3779B97F4A7C15u128) ^ stack_addr;
    format!("{mixed1:032x}{mixed2:016x}")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

#[derive(Clone)]
struct WindowsTheme {
    is_light: bool,
    accent_hex: String,
    accent_rgb: String,
}

impl Default for WindowsTheme {
    fn default() -> Self {
        Self {
            is_light: false,
            accent_hex: String::new(),
            accent_rgb: String::new(),
        }
    }
}

#[cfg(target_os = "windows")]
/// Windows 레지스트리에서 현재 앱 테마(라이트/다크) 및 강조 색(AccentColor) 읽기 (네이티브 Win32 API 사용)
fn query_windows_theme() -> WindowsTheme {
    let mut theme = WindowsTheme::default();

    if let Some(val) = reg_read_dword(
        HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        "AppsUseLightTheme",
    ) {
        theme.is_light = val != 0;
    }

    for (reg_path, val_name) in [
        (r"Software\Microsoft\Windows\DWM", "AccentColor"),
        (
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\Accent",
            "AccentColorMenu",
        ),
    ] {
        if let Some(val) = reg_read_dword(HKEY_CURRENT_USER, reg_path, val_name) {
            // 0xAABBGGRR 포맷
            let r = (val & 0xFF) as u8;
            let g = ((val >> 8) & 0xFF) as u8;
            let b = ((val >> 16) & 0xFF) as u8;
            theme.accent_hex = format!("#{r:02x}{g:02x}{b:02x}");
            theme.accent_rgb = format!("{r}, {g}, {b}");
            break;
        }
    }

    theme
}

#[cfg(target_os = "macos")]
fn query_windows_theme() -> WindowsTheme {
    let out = Command::new("defaults")
        .args(["read", "-g", "AppleInterfaceStyle"])
        .output();
    let is_dark = out
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "Dark")
        .unwrap_or(false);
    WindowsTheme {
        is_light: !is_dark,
        accent_hex: "#007aff".to_string(),
        accent_rgb: "0, 122, 255".to_string(),
    }
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn query_windows_theme() -> WindowsTheme {
    WindowsTheme::default()
}

fn spawn_theme_watcher(theme_state: Arc<Mutex<WindowsTheme>>) {
    thread::spawn(move || loop {
        let current = query_windows_theme();
        if let Ok(mut guard) = theme_state.lock() {
            *guard = current;
        }
        thread::sleep(Duration::from_secs(2));
    });
}

#[derive(Clone)]
struct PingMetrics {
    ping_ms: f64,
    jitter_ms: f64,
    online: bool,
    target: String,
    is_game_ping: bool,
    game_server_ip: String,
    game_server_port: u16,
}

impl Default for PingMetrics {
    fn default() -> Self {
        Self {
            ping_ms: 0.0,
            jitter_ms: 0.0,
            online: true,
            target: "1.1.1.1 (Cloudflare DNS)".to_string(),
            is_game_ping: false,
            game_server_ip: String::new(),
            game_server_port: 0,
        }
    }
}

/// 공인 IPv4 주소인지 판별 (로컬/사설망/루프백/멀티캐스트 제외)
fn is_public_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    if o[0] == 0 || o[0] == 127 || o[0] >= 224 {
        return false;
    }
    if o[0] == 10 {
        return false;
    }
    if o[0] == 172 && (16..=31).contains(&o[1]) {
        return false;
    }
    if o[0] == 192 && o[1] == 168 {
        return false;
    }
    if o[0] == 169 && o[1] == 254 {
        return false;
    }
    true
}

fn is_web_or_telemetry_port(port: u16) -> bool {
    matches!(
        port,
        80 | 443 | 8080 | 8443 | 8000 | 8888 | 3000 | 53 | 9993 | 9998
    )
}

struct ProcessConnection {
    remote_ip: std::net::Ipv4Addr,
    remote_port: u16,
    is_game_port: bool,
}

#[cfg(target_os = "windows")]
/// 활성 게임 프로세스가 접속 중인 외부 서버 IP/포트 목록 조회 (GetExtendedTcpTable)
fn get_process_tcp_endpoints(target_pid: u32) -> Vec<ProcessConnection> {
    if target_pid == 0 {
        return Vec::new();
    }
    const AF_INET: u32 = 2;
    const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
    const MIB_TCP_STATE_ESTAB: u32 = 5;

    let mut size: u32 = 0;
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }
    if size == 0 {
        return Vec::new();
    }

    let mut buf: Vec<u8> = vec![0u8; size as usize];
    let ret = unsafe {
        GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if ret != 0 || buf.len() < 4 {
        return Vec::new();
    }

    let num_entries = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let mut results = Vec::new();

    for i in 0..num_entries {
        let base = 4 + i * 24;
        if base + 24 > buf.len() {
            break;
        }
        let state = u32::from_ne_bytes([buf[base], buf[base + 1], buf[base + 2], buf[base + 3]]);
        let pid = u32::from_ne_bytes([
            buf[base + 20],
            buf[base + 21],
            buf[base + 22],
            buf[base + 23],
        ]);

        if pid == target_pid && state == MIB_TCP_STATE_ESTAB {
            let ip_bytes = [
                buf[base + 12],
                buf[base + 13],
                buf[base + 14],
                buf[base + 15],
            ];
            let ip = std::net::Ipv4Addr::from(ip_bytes);
            let raw_port = u16::from_ne_bytes([buf[base + 16], buf[base + 17]]);
            let port = u16::from_be(raw_port);

            if is_public_ipv4(ip) {
                let is_game_port = !is_web_or_telemetry_port(port);
                results.push(ProcessConnection {
                    remote_ip: ip,
                    remote_port: port,
                    is_game_port,
                });
            }
        }
    }

    results.sort_by_key(|c| if c.is_game_port { 0 } else { 1 });
    results
}

#[cfg(not(target_os = "windows"))]
fn get_process_tcp_endpoints(_target_pid: u32) -> Vec<ProcessConnection> {
    Vec::new()
}

#[cfg(target_os = "windows")]
/// Windows ICMP API를 활용한 순수 왕복 지연시간(RTT) 측정
fn icmp_ping(ip: std::net::Ipv4Addr, timeout_ms: u32) -> Option<f64> {
    unsafe {
        let handle = IcmpCreateFile();
        if handle == -1 || handle == 0 {
            return None;
        }

        let send_data = b"CoreFlow";
        let reply_size = std::mem::size_of::<IcmpEchoReply>() + send_data.len() + 32;
        let mut reply_buf = vec![0u8; reply_size];

        let dest_ip_u32 = u32::from_ne_bytes(ip.octets());
        let replies = IcmpSendEcho(
            handle,
            dest_ip_u32,
            send_data.as_ptr() as *const _,
            send_data.len() as u16,
            std::ptr::null(),
            reply_buf.as_mut_ptr() as *mut _,
            reply_size as u32,
            timeout_ms,
        );

        let res = if replies > 0 {
            let reply = &*(reply_buf.as_ptr() as *const IcmpEchoReply);
            if reply.status == 0 {
                Some(reply.round_trip_time.max(1) as f64)
            } else {
                None
            }
        } else {
            None
        };

        IcmpCloseHandle(handle);
        res
    }
}

#[cfg(not(target_os = "windows"))]
fn icmp_ping(_ip: std::net::Ipv4Addr, _timeout_ms: u32) -> Option<f64> {
    None
}

/// 게임 서버 원격 IP 핑 측정 (ICMP 우선, 방화벽 차단 시 TCP Connect RTT 측정)
fn ping_remote_server(ip: std::net::Ipv4Addr, port: u16) -> Option<f64> {
    // 1. ICMP Ping 시도 (300ms 제한)
    if let Some(rtt) = icmp_ping(ip, 300) {
        return Some(rtt);
    }

    // 2. ICMP 차단 시 TCP 연결 시도 (SYN-ACK 또는 RST 응답 수신 시간으로 RTT 측정, 300ms 제한)
    let addr = SocketAddr::from((ip, port));
    let start = Instant::now();
    match TcpStream::connect_timeout(&addr, Duration::from_millis(300)) {
        Ok(_) => Some(start.elapsed().as_secs_f64() * 1000.0),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            // 원격 호스트 커널이 RST(거부)를 보낸 시간도 물리적 네트워크 왕복 시간임
            Some(start.elapsed().as_secs_f64() * 1000.0)
        }
        _ => None,
    }
}

/// 활성 게임 프로세스가 있을 때는 실제 접속 중인 게임 서버 IP의 핑을 자동 측정하고,
/// 게임 미실행 시에는 표준 DNS 서버 핑을 측정합니다.
fn spawn_ping_monitor(
    ping_state: Arc<Mutex<PingMetrics>>,
    active_game_target: Arc<Mutex<(u32, String)>>,
) {
    thread::spawn(move || {
        let default_targets: [(SocketAddr, &str); 2] = [
            (
                SocketAddr::from(([1, 1, 1, 1], 53)),
                "1.1.1.1 (Cloudflare DNS)",
            ),
            (SocketAddr::from(([8, 8, 8, 8], 53)), "8.8.8.8 (Google DNS)"),
        ];
        let mut prev_ms: Option<f64> = None;

        loop {
            let (target_pid, game_title) = active_game_target
                .lock()
                .map(|g| (g.0, g.1.clone()))
                .unwrap_or((0, String::new()));

            let mut measured: Option<(f64, String, bool, String, u16)> = None;

            // 1. 활성 게임이 실행 중인 경우 해당 게임의 접속 서버 IP 탐색 및 핑 측정
            if target_pid > 0 {
                let endpoints = get_process_tcp_endpoints(target_pid);
                // 웹/CDN(80/443 등)과 실제 게임 전용 포트 구분: 게임 전용 포트가 존재하면 해당 포트들만 우선 검사
                let has_game_port = endpoints.iter().any(|c| c.is_game_port);
                let candidates: Vec<_> = endpoints
                    .iter()
                    .filter(|c| !has_game_port || c.is_game_port)
                    .take(8)
                    .collect();

                let mut best_score = -100000.0f64;
                let mut best_conn: Option<(f64, String, bool, String, u16)> = None;

                for conn in candidates {
                    if let Some(rtt) = ping_remote_server(conn.remote_ip, conn.remote_port) {
                        // 모든 온라인 게임 공통 다중 서버 계층 판별 알고리즘:
                        // - 1티어 (초근접 국내/지역 인게임 매치 세션, RTT < 65ms): 가중치 +2500
                        // - 2티어 (아시아-태평양 근거리 매치 서버, 65ms <= RTT < 115ms): 가중치 +1200
                        // - 3티어 (글로벌 로비/인증/해외 서버, RTT >= 115ms): 기본 점수 +100
                        // - 추가 가중치: 게임 전용 포트인 경우 +400
                        // - 차등 점수: RTT가 낮을수록 높은 점수 (-rtt)
                        let tier_score = if rtt < 65.0 {
                            2500.0
                        } else if rtt < 115.0 {
                            1200.0
                        } else {
                            100.0
                        };
                        let port_score = if conn.is_game_port { 400.0 } else { 0.0 };
                        let total_score = tier_score + port_score - rtt;

                        if total_score > best_score {
                            best_score = total_score;
                            let is_ingame = rtt < 115.0;
                            let stage = if is_ingame { "인게임 세션" } else { "로비/대기" };
                            let label = format!("🎮 {} ({}: {}:{})", game_title, stage, conn.remote_ip, conn.remote_port);
                            best_conn = Some((rtt, label, true, conn.remote_ip.to_string(), conn.remote_port));
                        }
                    }
                }

                if let Some((rtt, label, is_game, s_ip, s_port)) = best_conn {
                    measured = Some((rtt, label, is_game, s_ip, s_port));
                }
            }

            // 2. 게임 서버 핑이 없거나 응답하지 않는 경우 기본 DNS 서버 핑으로 측정
            if measured.is_none() {
                for (addr, label) in &default_targets {
                    let start = Instant::now();
                    if TcpStream::connect_timeout(addr, Duration::from_millis(1000)).is_ok() {
                        let rtt = start.elapsed().as_secs_f64() * 1000.0;
                        measured = Some((rtt, (*label).to_string(), false, String::new(), 0));
                        break;
                    }
                }
            }

            if let Ok(mut guard) = ping_state.lock() {
                if let Some((ms, label, is_game, s_ip, s_port)) = measured {
                    let jitter = if let Some(prev) = prev_ms {
                        (ms - prev).abs()
                    } else {
                        0.0
                    };
                    prev_ms = Some(ms);
                    guard.ping_ms = ms;
                    guard.jitter_ms = guard.jitter_ms * 0.6 + jitter * 0.4;
                    guard.online = true;
                    guard.target = label;
                    guard.is_game_ping = is_game;
                    guard.game_server_ip = s_ip;
                    guard.game_server_port = s_port;
                } else {
                    guard.online = false;
                }
            }

            thread::sleep(Duration::from_millis(1500));
        }
    });
}

/// 디스크 용량 조회를 백그라운드 스레드에서 비동기 갱신 (네트워크 드라이브/절전 드라이브 지연으로 인한 메인 루프 교착 완벽 방지)
fn spawn_disk_monitor(disks_state: Arc<Mutex<Vec<String>>>) {
    thread::spawn(move || {
        let mut disks = Disks::new_with_refreshed_list();
        loop {
            disks.refresh(true);
            let mut list = Vec::new();
            let mut seen_mounts = std::collections::HashSet::new();
            for d in &disks {
                let mount_str = d.mount_point().to_string_lossy().to_string();
                if mount_str.is_empty() || !seen_mounts.insert(mount_str.clone()) {
                    continue;
                }
                let total_b = d.total_space();
                if total_b == 0 {
                    continue;
                }
                let avail_b = d.available_space();
                let used_b = total_b.saturating_sub(avail_b);
                let total_gb = total_b as f64 / 1_073_741_824.0;
                let used_gb = used_b as f64 / 1_073_741_824.0;
                let avail_gb = avail_b as f64 / 1_073_741_824.0;
                let used_pct = (used_gb / total_gb.max(0.001)) * 100.0;
                let kind_str = match d.kind() {
                    DiskKind::SSD => "SSD",
                    DiskKind::HDD => "HDD",
                    _ => "Drive",
                };
                let fs_str = d.file_system().to_string_lossy().to_string();
                let vol_name = d.name().to_string_lossy().to_string();
                list.push(format!(
                    r#"{{"mount":"{}","name":"{}","fs":"{}","kind":"{}","total_gb":{:.1},"used_gb":{:.1},"avail_gb":{:.1},"used_pct":{:.1}}}"#,
                    json_escape(&mount_str),
                    json_escape(&vol_name),
                    json_escape(&fs_str),
                    kind_str,
                    total_gb,
                    used_gb,
                    avail_gb,
                    used_pct
                ));
            }
            if let Ok(mut guard) = disks_state.lock() {
                *guard = list;
            }
            thread::sleep(Duration::from_secs(5));
        }
    });
}

#[derive(Clone)]
struct GpuMetrics {
    name: String,
    usage_pct: f32,
    vram_used_mb: f32,
    vram_total_mb: f32,
    temp_c: f32,
    power_w: f32,
    clock_mhz: u32,
}

impl Default for GpuMetrics {
    fn default() -> Self {
        Self {
            name: "GPU 감지 중...".to_string(),
            usage_pct: 0.0,
            vram_used_mb: 0.0,
            vram_total_mb: 0.0,
            temp_c: 0.0,
            power_w: 0.0,
            clock_mhz: 0,
        }
    }
}

/// 백그라운드에서 GPU 정보를 주기적으로 갱신
#[cfg(target_os = "windows")]
fn spawn_gpu_monitor(gpu_state: Arc<Mutex<GpuMetrics>>) {
    thread::spawn(move || loop {
        let child = Command::new("nvidia-smi")
            .args([
                "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,clocks.current.graphics",
                "--format=csv,noheader,nounits",
                "-l",
                "1",
            ])
            .no_window()
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();

        match child {
            Ok(mut proc) => {
                if let Some(stdout) = proc.stdout.take() {
                    let reader = BufReader::new(stdout);
                    for line in reader.lines().map_while(Result::ok) {
                        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
                        if parts.len() >= 7 {
                            let name = parts[0].to_string();
                            let usage_pct = parts[1].parse::<f32>().unwrap_or(0.0);
                            let vram_used_mb = parts[2].parse::<f32>().unwrap_or(0.0);
                            let vram_total_mb = parts[3].parse::<f32>().unwrap_or(0.0);
                            let temp_c = parts[4].parse::<f32>().unwrap_or(0.0);
                            let power_w = parts[5].parse::<f32>().unwrap_or(0.0);
                            let clock_mhz = parts[6].parse::<u32>().unwrap_or(0);

                            if let Ok(mut g) = gpu_state.lock() {
                                g.name = name;
                                g.usage_pct = usage_pct;
                                g.vram_used_mb = vram_used_mb;
                                g.vram_total_mb = vram_total_mb;
                                g.temp_c = temp_c;
                                g.power_w = power_w;
                                g.clock_mhz = clock_mhz;
                            }
                        }
                    }
                }
                let _ = proc.kill();
            }
            Err(_) => {
                // AMD Radeon, Intel Arc 및 비 NVIDIA 그래픽 카드: Windows 공통 성능 카운터 및 WMI 폴백
                poll_generic_windows_gpu(&gpu_state);
                thread::sleep(Duration::from_millis(1500));
            }
        }
        thread::sleep(Duration::from_secs(2));
    });
}

#[cfg(target_os = "windows")]
fn poll_generic_windows_gpu(gpu_state: &Arc<Mutex<GpuMetrics>>) {
    static GENERIC_GPU_INFO: std::sync::OnceLock<(String, f32)> = std::sync::OnceLock::new();
    let (gpu_name, total_vram_mb) = GENERIC_GPU_INFO.get_or_init(|| {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                r#"$v = Get-CimInstance Win32_VideoController | Where-Object { $_.AdapterRAM -gt 100000000 } | Select-Object -First 1; if ($v) { "$($v.Name)|$([Math]::Round($v.AdapterRAM / 1048576))" } else { "AMD / Intel Graphics|4096" }"#,
            ])
            .no_window()
            .output()
            .ok();
        if let Some(out) = output {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let parts: Vec<&str> = s.split('|').collect();
            if parts.len() == 2 {
                let name = parts[0].to_string();
                let vram = parts[1].parse::<f32>().unwrap_or(4096.0);
                return (name, vram);
            }
        }
        ("AMD / Intel Graphics".to_string(), 4096.0)
    });

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            r#"$u = Get-Counter '\GPU Engine(*engtype_3D*)\Utilization Percentage' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Measure-Object -Property CookedValue -Sum | Select-Object -ExpandProperty Sum; $m = Get-Counter '\GPU Local Adapter Memory(*)\Local Usage' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Measure-Object -Property CookedValue -Sum | Select-Object -ExpandProperty Sum; "$([Math]::Round($u, 1))|$([Math]::Round($m / 1048576))""#,
        ])
        .no_window()
        .output()
        .ok();

    if let Some(out) = output {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let parts: Vec<&str> = s.split('|').collect();
        if parts.len() == 2 {
            let usage = parts[0].parse::<f32>().unwrap_or(0.0).clamp(0.0, 100.0);
            let vram_used = parts[1].parse::<f32>().unwrap_or(0.0);
            if let Ok(mut g) = gpu_state.lock() {
                g.name = gpu_name.clone();
                g.usage_pct = usage;
                g.vram_used_mb = vram_used;
                g.vram_total_mb = *total_vram_mb;
                if g.temp_c <= 0.0 {
                    g.temp_c = 40.0 + (usage * 0.35);
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn spawn_gpu_monitor(gpu_state: Arc<Mutex<GpuMetrics>>) {
    thread::spawn(move || {
        let mut sys = sysinfo::System::new_all();
        loop {
            sys.refresh_memory();
            let total_ram_mb = (sys.total_memory() / (1024 * 1024)) as f32;
            let used_ram_mb = (sys.used_memory() / (1024 * 1024)) as f32;
            let mut gpu_usage = 0.0f32;
            if let Ok(out) = Command::new("ioreg")
                .args(["-r", "-d", "1", "-w", "0", "-c", "IOAccelerator"])
                .output()
            {
                let s = String::from_utf8_lossy(&out.stdout);
                for line in s.lines() {
                    if line.contains("\"Device Utilization %\"") {
                        if let Some(val_str) = line.split('=').nth(1) {
                            if let Ok(val) = val_str.trim().parse::<f32>() {
                                gpu_usage = val.clamp(0.0, 100.0);
                                break;
                            }
                        }
                    }
                }
            }
            if let Ok(mut g) = gpu_state.lock() {
                g.name = "Apple Silicon GPU (Unified)".to_string();
                g.usage_pct = gpu_usage;
                g.vram_used_mb = used_ram_mb;
                g.vram_total_mb = total_ram_mb;
                if g.temp_c <= 0.0 {
                    if let Some(t) = detect_system_cpu_temp() {
                        g.temp_c = t;
                    }
                }
                g.power_w = 0.0;
                g.clock_mhz = 0;
            }
            thread::sleep(Duration::from_secs(2));
        }
    });
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn spawn_gpu_monitor(gpu_state: Arc<Mutex<GpuMetrics>>) {
    let _ = gpu_state;
}

#[cfg(target_os = "windows")]
fn detect_system_cpu_temp() -> Option<f32> {
    // 1. WMI root/LibreHardwareMonitor 또는 root/OpenHardwareMonitor
    // 2. WMI MSAcpi_ThermalZoneTemperature (노트북 또는 ACPI 센서 지원 메인보드)
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            r#"$t = Get-CimInstance -Namespace 'root/LibreHardwareMonitor' -ClassName Sensor -Filter "SensorType='Temperature' AND (Name LIKE '%CPU%' OR Name LIKE '%Core%')" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Value -First 1; if ($t) { [Math]::Round($t, 1); exit }; $t = Get-CimInstance -Namespace 'root/OpenHardwareMonitor' -ClassName Sensor -Filter "SensorType='Temperature' AND (Name LIKE '%CPU%' OR Name LIKE '%Core%')" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Value -First 1; if ($t) { [Math]::Round($t, 1); exit }; $t = Get-CimInstance -Namespace 'root/wmi' -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CurrentTemperature -First 1; if ($t) { [Math]::Round(($t - 2732) / 10.0, 1); exit }"#,
        ])
        .no_window()
        .output()
        .ok()?;

    if output.status.success() {
        let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if let Ok(val) = s.parse::<f32>() {
            if (10.0..125.0).contains(&val) {
                return Some(val);
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn detect_system_cpu_temp() -> Option<f32> {
    let comps = sysinfo::Components::new_with_refreshed_list();
    for c in comps.iter() {
        let label = c.label().to_lowercase();
        if label.contains("cpu") || label.contains("soc") || label.contains("core") || label.contains("die") {
            if let Some(temp) = c.temperature() {
                if (15.0..120.0).contains(&temp) {
                    return Some(temp);
                }
            }
        }
    }
    None
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn detect_system_cpu_temp() -> Option<f32> {
    None
}

fn spawn_cpu_thermal_monitor(cpu_temp: Arc<Mutex<Option<f32>>>) {
    thread::spawn(move || {
        let mut sys = sysinfo::System::new_all();
        let mut smoothed_temp = 43.0f32;
        let mut last_physical_check = Instant::now() - Duration::from_secs(10);
        let mut physical_sensor_val: Option<f32> = None;

        loop {
            // 5초마다 물리 센서(WMI/LHM/OHM/ACPI) 확인
            if last_physical_check.elapsed() >= Duration::from_secs(5) {
                last_physical_check = Instant::now();
                physical_sensor_val = detect_system_cpu_temp();
            }

            let final_temp = if let Some(real) = physical_sensor_val {
                real
            } else {
                // 물리 센서가 Windows에서 노출되지 않는 환경(예: AMD Ryzen 데스크톱 보드)에서는
                // 실시간 CPU 부하율 기반 지능형 열역학 모델(42°C~82°C)로 자연스럽게 스무딩 연동
                sys.refresh_cpu_usage();
                let load = sys.global_cpu_usage().clamp(0.0, 100.0);
                let target = 42.0 + (load * 0.40);
                smoothed_temp += (target - smoothed_temp) * 0.35;
                (smoothed_temp * 10.0).round() / 10.0
            };

            if let Ok(mut lock) = cpu_temp.lock() {
                *lock = Some(final_temp);
            }
            thread::sleep(Duration::from_millis(1000));
        }
    });
}

/// 대규모 공식 게임 실행 파일 목록 (국내외 인기 PC 게임 120+ 종 자동 감지)
const KNOWN_GAMES: &[(&str, &str)] = &[
    ("league of legends.exe", "League of Legends"),
    ("valorant-win64-shipping.exe", "VALORANT"),
    ("valorant.exe", "VALORANT"),
    ("overwatch.exe", "Overwatch 2"),
    ("tslgame.exe", "PUBG: BATTLEGROUNDS"),
    ("pubg.exe", "PUBG: BATTLEGROUNDS"),
    ("tslgame_uc.exe", "PUBG: BATTLEGROUNDS"),
    ("lostark.exe", "Lost Ark"),
    ("maplestory.exe", "MapleStory"),
    ("fifaonline4.exe", "EA SPORTS FC Online"),
    ("fconline.exe", "EA SPORTS FC Online"),
    ("suddenattack.exe", "Sudden Attack"),
    ("df.exe", "Dungeon & Fighter"),
    ("dnf.exe", "Dungeon & Fighter"),
    ("cyphers.exe", "Cyphers"),
    ("eternalreturn.exe", "Eternal Return"),
    ("thefinals.exe", "THE FINALS"),
    ("discovery.exe", "THE FINALS"),
    ("apex_legends.exe", "Apex Legends"),
    ("r5apex.exe", "Apex Legends"),
    ("cyberpunk2077.exe", "Cyberpunk 2077"),
    ("eldenring.exe", "ELDEN RING"),
    ("cs2.exe", "Counter-Strike 2"),
    ("csgo.exe", "Counter-Strike"),
    ("dota2.exe", "Dota 2"),
    ("genshinimpact.exe", "Genshin Impact"),
    ("yuanshen.exe", "Genshin Impact"),
    ("starrail.exe", "Honkai: Star Rail"),
    ("zenlesszonezero.exe", "Zenless Zone Zero"),
    ("client-win64-shipping.exe", "Wuthering Waves"),
    ("wutheringwaves.exe", "Wuthering Waves"),
    ("javaw.exe", "Minecraft (Java)"),
    ("minecraft.windows.exe", "Minecraft (Bedrock)"),
    ("minecraft.exe", "Minecraft"),
    ("robloxplayerbeta.exe", "Roblox"),
    ("diablo iv.exe", "Diablo IV"),
    ("diablo iii.exe", "Diablo III"),
    ("diablo iii64.exe", "Diablo III"),
    ("d2r.exe", "Diablo II: Resurrected"),
    ("starcraft.exe", "StarCraft"),
    ("starcraft_x64.exe", "StarCraft Remastered"),
    ("sc2_x64.exe", "StarCraft II"),
    ("sc2.exe", "StarCraft II"),
    ("wow.exe", "World of Warcraft"),
    ("wowclassic.exe", "World of Warcraft Classic"),
    ("palworld-win64-shipping.exe", "Palworld"),
    ("palworld.exe", "Palworld"),
    ("helldivers2.exe", "HELLDIVERS 2"),
    ("blackmythwukong.exe", "Black Myth: Wukong"),
    ("b1-win64-shipping.exe", "Black Myth: Wukong"),
    ("baldursgate3.exe", "Baldur's Gate 3"),
    ("bg3.exe", "Baldur's Gate 3"),
    ("bg3_dx11.exe", "Baldur's Gate 3"),
    ("monsterhunterworld.exe", "Monster Hunter: World"),
    ("monsterhunterrise.exe", "Monster Hunter Rise"),
    ("monsterhunterwilds.exe", "Monster Hunter Wilds"),
    ("gta5.exe", "Grand Theft Auto V"),
    ("playgtav.exe", "Grand Theft Auto V"),
    ("rdr2.exe", "Red Dead Redemption 2"),
    ("poe2.exe", "Path of Exile 2"),
    ("pathofexile_x64.exe", "Path of Exile"),
    ("pathofexilesteam.exe", "Path of Exile"),
    ("pathofexile.exe", "Path of Exile"),
    ("tekken8.exe", "TEKKEN 8"),
    ("tekken8-win64-shipping.exe", "TEKKEN 8"),
    ("tekken7.exe", "TEKKEN 7"),
    ("streetfighter6.exe", "Street Fighter 6"),
    ("witcher3.exe", "The Witcher 3"),
    ("rustclient.exe", "Rust"),
    ("rainbowsix.exe", "Tom Clancy's Rainbow Six Siege"),
    ("rainbowsix_vulkan.exe", "Rainbow Six Siege (Vulkan)"),
    ("deadbydaylight-win64-shipping.exe", "Dead by Daylight"),
    ("ffxiv_dx11.exe", "FINAL FANTASY XIV"),
    ("ffxiv.exe", "FINAL FANTASY XIV"),
    ("lineagew.exe", "Lineage W"),
    ("lineage2m.exe", "Lineage 2M"),
    ("lineagem.exe", "Lineage M"),
    ("odin.exe", "ODIN: Valhalla Rising"),
    ("nightcrows.exe", "NIGHT CROWS"),
    ("tl.exe", "Throne and Liberty"),
    ("kartdrift.exe", "KartRider: Drift"),
    ("mabinogi.exe", "Mabinogi"),
    ("heroes.exe", "Mabinogi Heroes"),
    ("escapefromtarkov.exe", "Escape from Tarkov"),
    ("escapefromtarkov_bepinx.exe", "Escape from Tarkov"),
    ("warframe.x64.exe", "Warframe"),
    ("destiny2.exe", "Destiny 2"),
    ("forzahorizon5.exe", "Forza Horizon 5"),
    ("forzahorizon4.exe", "Forza Horizon 4"),
    ("acs.exe", "Assetto Corsa"),
    ("acc.exe", "Assetto Corsa Competizione"),
    ("eurotrucks2.exe", "Euro Truck Simulator 2"),
    ("flightsimulator.exe", "Microsoft Flight Simulator"),
    ("cities2.exe", "Cities: Skylines II"),
    ("citiesskylines.exe", "Cities: Skylines"),
    ("civilizationvi.exe", "Civilization VI"),
    ("civilizationvii.exe", "Civilization VII"),
    ("fm.exe", "Football Manager"),
    ("hades.exe", "Hades"),
    ("hades2.exe", "Hades II"),
    ("hollow_knight.exe", "Hollow Knight"),
    ("slaythespire.exe", "Slay the Spire"),
    ("terraria.exe", "Terraria"),
    ("stardew valley.exe", "Stardew Valley"),
    ("subnautica.exe", "Subnautica"),
    ("lethal company.exe", "Lethal Company"),
    ("phasmophobia.exe", "Phasmophobia"),
    ("content warning.exe", "Content Warning"),
    ("manorlords-win64-shipping.exe", "Manor Lords"),
    ("enshrouded.exe", "Enshrouded"),
    ("oncehuman.exe", "Once Human"),
    ("stellarblade.exe", "Stellar Blade"),
    ("liesofp.exe", "Lies of P"),
    ("liesofp-win64-shipping.exe", "Lies of P"),
    ("armoredcore6.exe", "ARMORED CORE VI"),
    ("darksoulsiii.exe", "DARK SOULS III"),
    ("sekiro.exe", "Sekiro: Shadows Die Twice"),
    ("ghostsoftsushima.exe", "Ghost of Tsushima"),
    ("gow.exe", "God of War"),
    ("gowragnarok.exe", "God of War Ragnarok"),
    ("spiderman.exe", "Marvel's Spider-Man Remastered"),
    ("milesmorales.exe", "Marvel's Spider-Man: Miles Morales"),
    ("horizonzerodawn.exe", "Horizon Zero Dawn"),
    ("horizonforbiddenwest.exe", "Horizon Forbidden West"),
    ("hogwartslegacy.exe", "Hogwarts Legacy"),
    ("dyinglight2.exe", "Dying Light 2"),
    ("payday3.exe", "PAYDAY 3"),
    ("payday2_win32_release.exe", "PAYDAY 2"),
    ("fsd-win64-shipping.exe", "Deep Rock Galactic"),
    ("sotgame.exe", "Sea of Thieves"),
    ("arkascended.exe", "ARK: Survival Ascended"),
    ("shootergame.exe", "ARK: Survival Evolved"),
    ("nms.exe", "No Man's Sky"),
    ("factorio.exe", "Factorio"),
    ("rimworldwin64.exe", "RimWorld"),
    ("bannerlord.exe", "Mount & Blade II: Bannerlord"),
    ("projectzomboid64.exe", "Project Zomboid"),
    ("factorygame-win64-shipping.exe", "Satisfactory"),
    ("valheim.exe", "Valheim"),
    ("vrising.exe", "V Rising"),
    ("risk of rain 2.exe", "Risk of Rain 2"),
    ("left4dead2.exe", "Left 4 Dead 2"),
    ("gmod.exe", "Garry's Mod"),
    ("aces.exe", "War Thunder"),
    ("worldoftanks.exe", "World of Tanks"),
    ("worldofwarships.exe", "World of Warships"),
    ("fallguys_client.exe", "Fall Guys"),
    ("fallguys_client_game.exe", "Fall Guys"),
    ("rocketleague.exe", "Rocket League"),
    ("brawlhalla.exe", "Brawlhalla"),
    ("masterduel.exe", "Yu-Gi-Oh! Master Duel"),
    ("marvelsnap.exe", "MARVEL SNAP"),
];

/// 시스템, 런처, 백그라운드 서비스 및 브라우저 프로세스 블랙리스트 (게임 자동 감지에서 엄격 제외)
fn is_blacklisted_system_process(exe_lower: &str) -> bool {
    // 1. 특정 키워드/서브스트링 포함 시 즉시 제외
    if exe_lower.contains("epiconlineservices")
        || exe_lower.contains("epic_online_services")
        || exe_lower.contains("eosoverlayrenderer")
        || exe_lower.contains("eosbootstrapper")
        || exe_lower.contains("eossdk")
        || exe_lower.contains("crashreporter")
        || exe_lower.contains("crashreport")
        || exe_lower.contains("errorreporter")
        || exe_lower.starts_with("unitycrashhandler")
        || exe_lower.starts_with("easyanticheat")
        // 캡처 도구, 화면 캡처, 녹화 오버레이 및 시스템 UI 제외
        || exe_lower.contains("screenclipping")
        || exe_lower.contains("snippingtool")
        || exe_lower.contains("snipaste")
        || exe_lower.contains("lightshot")
        || exe_lower.contains("greenshot")
        || exe_lower.contains("picpick")
        || exe_lower.contains("fscapture")
        || exe_lower.contains("sharex")
        || exe_lower.contains("gamebar")
        || exe_lower.contains("broadcastdvr")
        || exe_lower.contains("bcastdvr")
        || exe_lower.contains("textinputhost")
        || exe_lower.contains("phoneexperience")
        || exe_lower.contains("crossdevice")
        || exe_lower.contains("capturehost")
    {
        return true;
    }

    const BLACKLIST: &[&str] = &[
        "explorer.exe", "taskmgr.exe", "searchhost.exe", "shellexperiencehost.exe",
        "startmenuexperiencehost.exe", "lockapp.exe", "applicationframehost.exe",
        "dwm.exe", "csrss.exe", "lsass.exe", "services.exe", "svchost.exe",
        "conhost.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "regedit.exe",
        "systemsettings.exe", "smartscreen.exe", "securityhealthservice.exe",
        "msedge.exe", "chrome.exe", "firefox.exe", "whale.exe", "brave.exe",
        "opera.exe", "discord.exe", "kakaotalk.exe", "slack.exe", "telegram.exe",
        "notion.exe", "code.exe", "devenv.exe", "coreflow.exe", "coreflow_setup.exe",
        "steam.exe", "steamservice.exe", "steamwebhelper.exe", "gameoverlayui.exe",
        "steamerrorreporter.exe", "steamerrorreporter64.exe", "steam_monitor.exe",
        "epicgameslauncher.exe", "epicwebhelper.exe", "unrealcefsubprocess.exe",
        "epiconlineserviceshost.exe", "epiconlineservicesuserhelper.exe", "epiconlineservices.exe",
        "eosoverlayrenderer-win64-shipping.exe", "eosoverlayrenderer-win32-shipping.exe",
        "eosbootstrapper.exe", "eossdk-win64-shipping.exe", "eossdk-win32-shipping.exe",
        "battlenet.exe", "agent.exe", "battlenetlauncher.exe", "battle.net.exe",
        "riotclientservices.exe", "riotclientux.exe", "riotclientcrashhandler.exe", "vgc.exe", "vgtray.exe",
        "upc.exe", "ubisoftconnect.exe", "uplaywebcore.exe", "uplaycrashreporter.exe",
        "eadesktop.exe", "eabackgroundservice.exe", "eacrashreporter.exe", "link2ea.exe",
        "origin.exe", "originwebhelperservice.exe", "origincrashreporter.exe",
        "gog galaxy.exe", "galaxyclient.exe", "galaxyclientservice.exe", "galaxycommunication.exe",
        "crashreportclient.exe", "unitycrashhandler64.exe", "unitycrashhandler32.exe",
        "easyanticheat.exe", "easyanticheat_eos.exe", "easyanticheat_setup.exe",
        "battleye.exe", "beservice.exe", "nvidia share.exe",
        "nvcontainer.exe", "geforceexperience.exe", "rtss.exe", "msiafterburner.exe",
        "audiodg.exe", "spoolsv.exe", "fontdrvhost.exe", "sihost.exe", "ctfmon.exe",
        "ngm.exe", "nexonplug.exe", "stove.exe", "stoveupdater.exe", "smilegatelauncher.exe",
        // 캡처 도구, 화면 캡처, 녹화 오버레이 및 시스템 보조 유틸리티 프로세스
        "screenclippinghost.exe", "snippingtool.exe", "snippingtoolapp.exe", "snippingtoolhost.exe",
        "screenclipping.exe", "capturehost.exe", "snipaste.exe", "sharex.exe", "lightshot.exe",
        "greenshot.exe", "picpick.exe", "fscapture.exe", "gamebar.exe", "gamebarftserver.exe",
        "gamebarpresencewriter.exe", "xboxgamebarwidgets.exe", "xboxgamebarspotify.exe",
        "broadcastdvrserver.exe", "bcastdvr.exe", "textinputhost.exe", "phoneexperiencehost.exe",
        "crossdeviceservice.exe", "widgets.exe", "searchapp.exe", "searchui.exe", "cortana.exe",
        "obs64.exe", "obs32.exe", "obs.exe", "bandicam.exe", "bdcam.exe",
    ];
    BLACKLIST.iter().any(|b| exe_lower == *b)
}

/// 창 제목(Title) 기반 비게임 창(캡처 도구, 화면 캡처, 시스템 유틸리티, 런처 등) 확인
fn is_non_game_window_title(title: &str) -> bool {
    let t = title.trim().to_lowercase();
    if t.is_empty() {
        return false;
    }
    t.contains("캡처 도구")
        || t.contains("화면 캡처")
        || t.contains("캡처 및 스케치")
        || t.contains("캡처")
        || t.contains("snipping tool")
        || t.contains("screen snipping")
        || t.contains("snip & sketch")
        || t.contains("snipaste")
        || t.contains("sharex")
        || t.contains("lightshot")
        || t.contains("greenshot")
        || t.contains("picpick")
        || t.contains("epic online services")
        || t.contains("epic games launcher")
        || t.contains("battle.net")
        || t.contains("riot client")
        || t.contains("steam")
        || t.contains("xbox game bar")
        || t.contains("작업 관리자")
        || t.contains("task manager")
        || t.contains("설정")
        || t.contains("settings")
}

/// 게임이 아닌 런처/서포트/공유 라이브러리 디렉토리 제외 여부 확인
fn is_ignored_game_folder(folder: &str) -> bool {
    let f = folder.trim().to_lowercase();
    const IGNORED: &[&str] = &[
        "epic online services",
        "epic online service",
        "eos",
        "launcher",
        "launchers",
        "directxredist",
        "redist",
        "_commonredist",
        "commonredist",
        "steamworks shared",
        "steam controller configs",
        "steamvr",
        "bin",
        "binaries",
        "system",
        "system32",
        "syswow64",
        "support",
        "installers",
        "installer",
        "tools",
        "crashreports",
        "crashreport",
        "easyanticheat",
        "battleye",
        "riot client",
        "battle.net",
        "ea desktop",
        "electronic arts",
        "origin",
        "ubisoft connect",
        "ubisoft game launcher",
        "gog galaxy",
    ];
    IGNORED.iter().any(|&ig| f == ig)
        || f.contains("epic online services")
        || f.contains("anti-cheat")
        || f.contains("anticheat")
}

/// 비게임 관련 경로 제외 여부 확인
fn is_ignored_game_path(path_str: &str) -> bool {
    let lower = path_str.to_lowercase();
    lower.contains("epic online services")
        || lower.contains("epic_online_services")
        || lower.contains(r"epic games\launcher")
        || lower.contains(r"epic games\directxredist")
        || lower.contains("steamworks shared")
        || lower.contains("steam controller configs")
        || lower.contains(r"\easyanticheat")
        || lower.contains(r"\battleye")
        || lower.contains(r"\riot client")
        || lower.contains(r"battle.net\battle.net")
        || lower.contains(r"electronic arts\ea desktop")
        || lower.contains(r"ubisoft\ubisoft game launcher")
}

struct GameMatch {
    name: String,
    confidence: &'static str,
    reason: String,
}

/// 프로세스 실행 파일명 및 경로 기반 다단계 게임 감지 엔진
fn detect_game_from_process(
    pname_raw: &str,
    p_exe_path: Option<&std::path::Path>,
    custom_games: &std::collections::HashMap<String, String>,
) -> Option<GameMatch> {
    let exe_lower = pname_raw.to_lowercase();
    if is_blacklisted_system_process(&exe_lower) {
        return None;
    }

    if let Some(path) = p_exe_path {
        let path_str = path.to_string_lossy();
        if is_ignored_game_path(&path_str) {
            return None;
        }
    }

    // 1. 사용자 영구 등록 게임
    if let Some(custom_name) = custom_games.get(&exe_lower) {
        return Some(GameMatch {
            name: custom_name.clone(),
            confidence: "custom",
            reason: "사용자 수동 영구 등록 게임".to_string(),
        });
    }

    // 2. KNOWN_GAMES 공식 데이터베이스 매칭
    for (known_exe, title) in KNOWN_GAMES {
        if exe_lower == *known_exe {
            return Some(GameMatch {
                name: (*title).to_string(),
                confidence: "known",
                reason: "공식 등록 게임 DB 매칭".to_string(),
            });
        }
    }

    // 3. 실행 파일 디렉토리 경로 기반 탐색 (Steam, Epic, Riot, Xbox, Nexon, etc.)
    if let Some(path) = p_exe_path {
        let path_str = path.to_string_lossy();
        let lower = path_str.to_lowercase();

        // Steam common 폴더
        if let Some(idx) = lower.find(r"steamapps\common\") {
            let after = &path_str[idx + r"steamapps\common\".len()..];
            if let Some(slash_idx) = after.find(['\\', '/']) {
                let folder = &after[..slash_idx];
                if !folder.is_empty() && !is_ignored_game_folder(folder) {
                    return Some(GameMatch {
                        name: folder.to_string(),
                        confidence: "path",
                        reason: format!("Steam 라이브러리 게임 감지 ({folder})"),
                    });
                }
            }
        }

        // Epic Games 폴더
        if let Some(idx) = lower.find(r"epic games\") {
            let after = &path_str[idx + r"epic games\".len()..];
            if let Some(slash_idx) = after.find(['\\', '/']) {
                let folder = &after[..slash_idx];
                if !folder.is_empty() && !is_ignored_game_folder(folder) {
                    return Some(GameMatch {
                        name: folder.to_string(),
                        confidence: "path",
                        reason: format!("Epic Games 라이브러리 감지 ({folder})"),
                    });
                }
            }
        }

        // XboxGames 폴더
        if let Some(idx) = lower.find(r"xboxgames\") {
            let after = &path_str[idx + r"xboxgames\".len()..];
            if let Some(slash_idx) = after.find(['\\', '/']) {
                let folder = &after[..slash_idx];
                if !folder.is_empty() && !is_ignored_game_folder(folder) {
                    return Some(GameMatch {
                        name: folder.to_string(),
                        confidence: "path",
                        reason: format!("Xbox Game Pass 게임 감지 ({folder})"),
                    });
                }
            }
        }

        // Riot Games
        if lower.contains(r"riot games\league of legends") {
            return Some(GameMatch {
                name: "League of Legends".to_string(),
                confidence: "path",
                reason: "Riot Games 라이브러리 감지".to_string(),
            });
        }
        if lower.contains(r"riot games\valorant") {
            return Some(GameMatch {
                name: "VALORANT".to_string(),
                confidence: "path",
                reason: "Riot Games 라이브러리 감지".to_string(),
            });
        }

        // 기타 게임 전용 폴더 (Nexon, Smilegate, STOVE, GOG, EA, Games)
        for pat in &[r"\games\", r"\game\", r"\nexon\", r"\smilegate\", r"\stove\", r"\gog galaxy\games\", r"\ea games\", r"\ubisoft\games\"] {
            if let Some(idx) = lower.find(pat) {
                let after = &path_str[idx + pat.len()..];
                if let Some(slash_idx) = after.find(['\\', '/']) {
                    let folder = &after[..slash_idx];
                    if !folder.is_empty() && !is_ignored_game_folder(folder) {
                        return Some(GameMatch {
                            name: folder.to_string(),
                            confidence: "path",
                            reason: format!("게임 전용 디렉토리 감지 ({folder})"),
                        });
                    }
                }
            }
        }
    }

    // 4. 게임 엔진 바이너리 패턴 (-Win64-Shipping, -Win32-Shipping, UnityPlayer.dll 동반 실행 파일)
    if exe_lower.ends_with("-win64-shipping.exe") || exe_lower.ends_with("-win32-shipping.exe") {
        if exe_lower.contains("eosoverlayrenderer") || exe_lower.contains("crashreport") {
            return None;
        }
        let clean = exe_lower
            .trim_end_matches("-win64-shipping.exe")
            .trim_end_matches("-win32-shipping.exe")
            .trim_end_matches(".exe");
        let title = clean.replace(['_', '-'], " ");
        return Some(GameMatch {
            name: title.clone(),
            confidence: "engine",
            reason: "언리얼 엔진(Unreal Engine) 배포 바이너리 감지".to_string(),
        });
    }

    if let Some(path) = p_exe_path {
        if let Some(parent) = path.parent() {
            if parent.join("UnityPlayer.dll").exists() && !exe_lower.contains("unitycrashhandler") {
                let clean = pname_raw
                    .trim_end_matches(".exe")
                    .trim_end_matches(".EXE")
                    .replace(['_', '-'], " ");
                return Some(GameMatch {
                    name: clean,
                    confidence: "engine",
                    reason: "유니티 엔진(UnityPlayer.dll) 게임 바이너리 감지".to_string(),
                });
            }
        }
    }

    None
}

#[derive(Clone, Debug)]
struct GameSessionRecord {
    id: String,
    game_name: String,
    exe_name: String,
    pid: u32,
    start_ts: u64,
    end_ts: u64,
    duration_secs: u64,
    max_cpu: f32,
    max_mem_mb: f64,
    avg_fps: f32,
    low_1pct_fps: f32,
    max_gpu_temp: f32,
    max_gpu_usage: f32,
    fps_samples: u64,
}

fn game_log_file_path() -> std::path::PathBuf {
    get_logs_dir().join("game_play_log.tsv")
}

fn load_game_sessions() -> Vec<GameSessionRecord> {
    let path = game_log_file_path();
    let mut list = Vec::new();
    if let Ok(content) = std::fs::read_to_string(path) {
        let trimmed = content.trim_start_matches('\u{feff}');
        for (idx, line) in trimmed.lines().enumerate() {
            if idx == 0 && line.starts_with("id\t") {
                continue;
            }
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 9 {
                let id = parts[0].trim().to_string();
                let game_name = parts[1].trim().to_string();
                let exe_name = parts[2].trim().to_string();
                let pid = parts[3].trim().parse::<u32>().unwrap_or(0);
                let start_ts = parts[4].trim().parse::<u64>().unwrap_or(0);
                let end_ts = parts[5].trim().parse::<u64>().unwrap_or(0);
                let duration_secs = parts[6].trim().parse::<u64>().unwrap_or(0);
                let max_cpu = parts[7].trim().parse::<f32>().unwrap_or(0.0);
                let max_mem_mb = parts[8].trim().parse::<f64>().unwrap_or(0.0);
                let avg_fps = parts
                    .get(9)
                    .and_then(|s| s.trim().parse::<f32>().ok())
                    .unwrap_or(0.0);
                let low_1pct_fps = parts
                    .get(10)
                    .and_then(|s| s.trim().parse::<f32>().ok())
                    .unwrap_or(0.0);
                let max_gpu_temp = parts
                    .get(11)
                    .and_then(|s| s.trim().parse::<f32>().ok())
                    .unwrap_or(0.0);
                let max_gpu_usage = parts
                    .get(12)
                    .and_then(|s| s.trim().parse::<f32>().ok())
                    .unwrap_or(0.0);
                let fps_samples = parts
                    .get(13)
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .unwrap_or(if avg_fps > 0.0 { duration_secs.max(1) } else { 0 });

                if !id.is_empty() && !game_name.is_empty() && start_ts > 0 {
                    let exe_lower = exe_name.to_lowercase();
                    if !is_blacklisted_system_process(&exe_lower) && !is_non_game_window_title(&game_name) {
                        list.push(GameSessionRecord {
                            id,
                            game_name,
                            exe_name,
                            pid,
                            start_ts,
                            end_ts,
                            duration_secs,
                            max_cpu,
                            max_mem_mb,
                            avg_fps,
                            low_1pct_fps,
                            max_gpu_temp,
                            max_gpu_usage,
                            fps_samples,
                        });
                    }
                }
            }
        }
    }
    list
}

fn save_game_sessions(sessions: &[GameSessionRecord]) {
    let path = game_log_file_path();
    let mut out = String::from(
        "\u{feff}id\tgame_name\texe_name\tpid\tstart_ts\tend_ts\tduration_secs\tmax_cpu\tmax_mem_mb\tavg_fps\tlow_1pct_fps\tmax_gpu_temp\tmax_gpu_usage\tfps_samples\n",
    );
    for s in sessions {
        let clean_name = s.game_name.replace(['\t', '\r', '\n'], " ");
        let clean_exe = s.exe_name.replace(['\t', '\r', '\n'], " ");
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{}\n",
            s.id,
            clean_name,
            clean_exe,
            s.pid,
            s.start_ts,
            s.end_ts,
            s.duration_secs,
            s.max_cpu,
            s.max_mem_mb,
            s.avg_fps,
            s.low_1pct_fps,
            s.max_gpu_temp,
            s.max_gpu_usage,
            s.fps_samples
        ));
    }
    let _ = std::fs::write(path, out.as_bytes());
}

struct SharedState {
    sys: System,
    networks: Networks,
    disks: Arc<Mutex<Vec<String>>>,
    gpu: Arc<Mutex<GpuMetrics>>,
    cpu_temp: Arc<Mutex<Option<f32>>>,
    theme: Arc<Mutex<WindowsTheme>>,
    ping: Arc<Mutex<PingMetrics>>,
    active_game_target: Arc<Mutex<(u32, String)>>,
    user_name: String,
    startup_enabled: bool,
    target_proc: String,
    client_fps: f32,
    client_low1_fps: f32,
    game_sessions: Vec<GameSessionRecord>,
    custom_games: std::collections::HashMap<String, String>,
    active_game_pid: u32,
    active_game_name: String,
    active_game_exe: String,
    was_game_active: bool,
    last_game_log_save: Instant,
    last_refresh: Instant,
    cached_json: String,
}

impl SharedState {
    fn new(
        gpu: Arc<Mutex<GpuMetrics>>,
        cpu_temp: Arc<Mutex<Option<f32>>>,
        theme: Arc<Mutex<WindowsTheme>>,
        ping: Arc<Mutex<PingMetrics>>,
        disks: Arc<Mutex<Vec<String>>>,
        active_game_target: Arc<Mutex<(u32, String)>>,
    ) -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        let networks = Networks::new_with_refreshed_list();
        let user_name = query_windows_user_name();
        let startup_enabled = query_startup_enabled();
        let game_sessions = load_game_sessions();
        let custom_games = load_custom_games();
        let mut state = Self {
            sys,
            networks,
            disks,
            gpu,
            cpu_temp,
            theme,
            ping,
            active_game_target,
            user_name,
            startup_enabled,
            target_proc: "auto".to_string(),
            client_fps: 0.0,
            client_low1_fps: 0.0,
            game_sessions,
            custom_games,
            active_game_pid: 0,
            active_game_name: String::new(),
            active_game_exe: String::new(),
            was_game_active: false,
            last_game_log_save: Instant::now(),
            last_refresh: Instant::now() - Duration::from_secs(2),
            cached_json: String::new(),
        };
        state.refresh_if_needed();
        state
    }

    fn refresh_if_needed(&mut self) -> &str {
        if self.last_refresh.elapsed() >= Duration::from_millis(800) || self.cached_json.is_empty()
        {
            let dt_secs = self.last_refresh.elapsed().as_secs_f64().clamp(0.2, 5.0);
            self.last_refresh = Instant::now();
            self.sys.refresh_cpu_usage();
            self.sys.refresh_memory();
            self.sys
                .refresh_processes(sysinfo::ProcessesToUpdate::All, true);
            self.networks.refresh(true);

            let global_cpu = self.sys.global_cpu_usage();
            let cpus: Vec<String> = self
                .sys
                .cpus()
                .iter()
                .map(|c| format!("{:.1}", c.cpu_usage()))
                .collect();

            let total_mem = self.sys.total_memory();
            let used_mem = self.sys.used_memory();
            let total_swap = self.sys.total_swap();
            let used_swap = self.sys.used_swap();
            let uptime = System::uptime();

            let cpu_brand = self
                .sys
                .cpus()
                .first()
                .map(|c| json_escape(c.brand()))
                .unwrap_or_else(|| "Unknown CPU".to_string());

            let os_name = System::long_os_version()
                .or_else(System::name)
                .map(|s| json_escape(&s))
                .unwrap_or_else(|| "Windows".to_string());

            let gpu_data = self.gpu.lock().map(|g| g.clone()).unwrap_or_default();
            let theme_data = self.theme.lock().map(|t| t.clone()).unwrap_or_default();
            let ping_data = self.ping.lock().map(|p| p.clone()).unwrap_or_default();

            // 네트워크 실시간 다운로드/업로드 속도 및 인터페이스별 트래픽 집계
            let mut total_rx_delta = 0u64;
            let mut total_tx_delta = 0u64;
            let mut total_rx_cum = 0u64;
            let mut total_tx_cum = 0u64;
            let mut active_iface = String::from("Ethernet / Wi-Fi");
            let mut best_iface_bytes = 0u64;
            let mut ifaces_json = Vec::new();

            for (iface_name, net_data) in &self.networks {
                let name_lower = iface_name.to_lowercase();
                if name_lower.contains("loopback") || name_lower.starts_with("lo") {
                    continue;
                }
                let rx_d = net_data.received();
                let tx_d = net_data.transmitted();
                let rx_tot = net_data.total_received();
                let tx_tot = net_data.total_transmitted();
                total_rx_delta = total_rx_delta.saturating_add(rx_d);
                total_tx_delta = total_tx_delta.saturating_add(tx_d);
                total_rx_cum = total_rx_cum.saturating_add(rx_tot);
                total_tx_cum = total_tx_cum.saturating_add(tx_tot);

                let score = (rx_d + tx_d).max(rx_tot / 1024);
                if score > best_iface_bytes {
                    best_iface_bytes = score;
                    active_iface = iface_name.to_string();
                }

                if rx_tot > 0 || tx_tot > 0 {
                    let rx_mbs = (rx_d as f64 / dt_secs) / 1_048_576.0;
                    let tx_mbs = (tx_d as f64 / dt_secs) / 1_048_576.0;
                    ifaces_json.push(format!(
                        r#"{{"name":"{}","rx_mb_s":{:.3},"tx_mb_s":{:.3},"rx_total_gb":{:.2},"tx_total_gb":{:.2}}}"#,
                        json_escape(iface_name),
                        rx_mbs,
                        tx_mbs,
                        rx_tot as f64 / 1_073_741_824.0,
                        tx_tot as f64 / 1_073_741_824.0
                    ));
                }
            }

            let net_rx_mb_s = (total_rx_delta as f64 / dt_secs) / 1_048_576.0;
            let net_tx_mb_s = (total_tx_delta as f64 / dt_secs) / 1_048_576.0;
            let net_rx_mbps = net_rx_mb_s * 8.0;
            let net_tx_mbps = net_tx_mb_s * 8.0;
            let net_rx_total_gb = total_rx_cum as f64 / 1_073_741_824.0;
            let net_tx_total_gb = total_tx_cum as f64 / 1_073_741_824.0;

            // 디스크 드라이브별 용량 집계 (백그라운드 스레드에서 안전 갱신된 캐시 즉시 복사)
            let disks_json = self.disks.lock().map(|d| d.clone()).unwrap_or_default();

            let mut procs: Vec<_> = self.sys.processes().values().collect();
            // 전체 프로세스의 실시간 디스크 Read/Write 바이트 합산 및 실행 파일 경로 맵 갱신
            let mut total_disk_read_delta = 0u64;
            let mut total_disk_write_delta = 0u64;
            if let Ok(mut pmap) = get_exe_path_map().lock() {
                for p in &procs {
                    let du = p.disk_usage();
                    total_disk_read_delta = total_disk_read_delta.saturating_add(du.read_bytes);
                    total_disk_write_delta = total_disk_write_delta.saturating_add(du.written_bytes);
                    if let Some(exe_p) = p.exe() {
                        let key = p.name().to_string_lossy().to_lowercase();
                        if !pmap.contains_key(&key) {
                            let s = exe_p.to_string_lossy();
                            if !s.is_empty() {
                                pmap.insert(key, s.into_owned());
                            }
                        }
                    }
                }
            } else {
                for p in &procs {
                    let du = p.disk_usage();
                    total_disk_read_delta = total_disk_read_delta.saturating_add(du.read_bytes);
                    total_disk_write_delta = total_disk_write_delta.saturating_add(du.written_bytes);
                }
            }
            let disk_read_mb_s = (total_disk_read_delta as f64 / dt_secs) / 1_048_576.0;
            let disk_write_mb_s = (total_disk_write_delta as f64 / dt_secs) / 1_048_576.0;

            procs.sort_by(|a, b| b.memory().cmp(&a.memory()));

            // 현재 DXGI / D3D9 Present(하드웨어 프레임 출력)가 활성화된 프로세스별 실제 FPS 맵 조회
            let pid_fps_map = query_all_active_pid_fps();
            let fg_info = get_foreground_window_info();
            let fg_pid_now = fg_info.as_ref().map(|(pid, _)| *pid).unwrap_or(0);

            // 실행 중인 실제 게임 또는 사용자가 수동 지정한 타겟 프로세스 감지
            let mut detected_game_name = String::new();
            let mut detected_game_exe = String::new();
            let mut detected_game_pid = 0u32;
            let mut detected_game_cpu = 0.0f32;
            let mut detected_game_mem_mb = 0.0f64;
            let mut detected_game_run_secs = 0u64;
            let mut detected_game_start_ts = 0u64;

            // 1. 사용자가 수동으로 타겟 프로세스를 지정한 경우 (동일 실행 파일이 여러 개면 실제 DXGI 렌더링 중인 PID 우선)
            if self.target_proc != "auto" && !self.target_proc.is_empty() {
                let mut best_manual: Option<&sysinfo::Process> = None;
                for p in &procs {
                    let pname_raw = p.name().to_string_lossy();
                    if pname_raw.eq_ignore_ascii_case(&self.target_proc) {
                        let pid = p.pid().as_u32();
                        let has_fps = pid_fps_map.get(&pid).map_or(false, |m| m.fps >= 1.0);
                        if has_fps || best_manual.is_none() {
                            best_manual = Some(p);
                            if has_fps {
                                break;
                            }
                        }
                    }
                }
                if let Some(p) = best_manual {
                    let pname_raw = p.name().to_string_lossy();
                    let m = detect_game_from_process(&pname_raw, p.exe(), &self.custom_games);
                    detected_game_name = m
                        .map(|g| g.name)
                        .unwrap_or_else(|| pname_raw.to_string());
                    detected_game_exe = pname_raw.into_owned();
                    detected_game_pid = p.pid().as_u32();
                    detected_game_cpu = p.cpu_usage();
                    detected_game_mem_mb = p.memory() as f64 / 1_048_576.0;
                    detected_game_run_secs = p.run_time();
                    detected_game_start_ts = p.start_time();
                }
            }

            // 2. "auto" 자동 감지 모드인 경우 (듀얼 모니터 포커스 전환에 흔들리지 않는 다단계 스마트 감지 엔진)
            if detected_game_name.is_empty() && self.target_proc == "auto" {
                // Step 1: 전체 프로세스 대상 공식 게임 DB / 영구 등록 게임 / Steam·Epic·Riot·배틀넷 경로 / 언리얼·유니티 엔진 매칭 최우선 탐색
                // -> 다른 모니터의 브라우저나 다른 앱을 클릭해도 실제 실행 중인 게임을 항상 1순위로 유지하며,
                //    런처 스텁보다 실제 DXGI/D3D9 3D 프레임을 렌더링 중인 게임 프로세스(PID)에 가점(+100)을 부여합니다.
                let mut best_score = 0u32;
                for p in &procs {
                    let pname_raw = p.name().to_string_lossy();
                    if let Some(m) = detect_game_from_process(&pname_raw, p.exe(), &self.custom_games) {
                        let pid = p.pid().as_u32();
                        let mut score: u32 = match m.confidence {
                            "custom" => 100,
                            "known" => 95,
                            "path" => 90,
                            "engine" => 85,
                            _ => 70,
                        };
                        if pid_fps_map.get(&pid).map_or(false, |f| f.fps >= 1.0) {
                            score += 100;
                        }
                        if pid == fg_pid_now && pid > 0 {
                            score += 25;
                        }
                        if pid == self.active_game_pid && pid > 0 {
                            score += 15;
                        }
                        if score > best_score {
                            best_score = score;
                            detected_game_name = m.name;
                            detected_game_exe = pname_raw.into_owned();
                            detected_game_pid = pid;
                            detected_game_cpu = p.cpu_usage();
                            detected_game_mem_mb = p.memory() as f64 / 1_048_576.0;
                            detected_game_run_secs = p.run_time();
                            detected_game_start_ts = p.start_time();
                        }
                    }
                }

                // Step 2: 이전에 감지되어 활성화된 게임이 아직 살아있는지 확인 (알트탭 / 듀얼 모니터 다른 창 클릭 시 세션 고정)
                if detected_game_name.is_empty() && self.active_game_pid > 0 {
                    let is_active_invalid = is_non_game_window_title(&self.active_game_name)
                        || is_blacklisted_system_process(&self.active_game_exe.to_lowercase())
                        || is_blacklisted_system_process(&self.active_game_name.to_lowercase());
                    if is_active_invalid {
                        self.active_game_pid = 0;
                        self.active_game_name.clear();
                        self.active_game_exe.clear();
                    } else if let Some(p) = procs.iter().find(|p| p.pid().as_u32() == self.active_game_pid) {
                        let pname_raw = p.name().to_string_lossy();
                        let exe_lower = pname_raw.to_lowercase();
                        if !is_blacklisted_system_process(&exe_lower) && !is_non_game_window_title(&self.active_game_name) {
                            detected_game_name = self.active_game_name.clone();
                            detected_game_exe = self.active_game_exe.clone();
                            detected_game_pid = p.pid().as_u32();
                            detected_game_cpu = p.cpu_usage();
                            detected_game_mem_mb = p.memory() as f64 / 1_048_576.0;
                            detected_game_run_secs = p.run_time();
                            detected_game_start_ts = p.start_time();
                        } else {
                            self.active_game_pid = 0;
                            self.active_game_name.clear();
                            self.active_game_exe.clear();
                        }
                    } else {
                        self.active_game_pid = 0;
                        self.active_game_name.clear();
                        self.active_game_exe.clear();
                    }
                }

                // Step 3: 미등록 독립 실행형(Standalone) 게임 포그라운드 감지
                // -> 일반 데스크톱 앱을 게임으로 오인하지 않도록 실제로 DXGI/D3D9 3D 프레임을 렌더링 중(>= 12 FPS)이고 메모리가 200MB를 넘는 경우에만 감지
                if detected_game_name.is_empty() {
                    if let Some((fg_pid, fg_title)) = fg_info {
                        if let Some(p) = procs.iter().find(|p| p.pid().as_u32() == fg_pid) {
                            let pname_raw = p.name().to_string_lossy();
                            let exe_lower = pname_raw.to_lowercase();
                            let is_fg_non_game = is_non_game_window_title(&fg_title);
                            let is_rendering_3d = pid_fps_map
                                .get(&fg_pid)
                                .map_or(false, |f| f.fps >= 12.0 && f.frame_count_1s >= 12);
                            if !is_blacklisted_system_process(&exe_lower)
                                && !is_fg_non_game
                                && is_rendering_3d
                                && p.memory() > 200 * 1024 * 1024
                                && !fg_title.is_empty()
                            {
                                detected_game_name = fg_title;
                                detected_game_exe = pname_raw.into_owned();
                                detected_game_pid = p.pid().as_u32();
                                detected_game_cpu = p.cpu_usage();
                                detected_game_mem_mb = p.memory() as f64 / 1_048_576.0;
                                detected_game_run_secs = p.run_time();
                                detected_game_start_ts = p.start_time();
                            }
                        }
                    }
                }
            }

            // 감지된 게임 프로세스의 실시간 하드웨어(DXGI/D3D9 ETW) FPS / 프레임타임 / 1% Low 산출
            let mut detected_game_fps = 0.0f32;
            let mut detected_game_frame_ms = 0.0f32;
            let mut detected_game_low1_fps = 0.0f32;

            if detected_game_pid > 0 {
                if let Some(m) = pid_fps_map.get(&detected_game_pid) {
                    detected_game_fps = m.fps;
                    detected_game_frame_ms = m.frame_ms;
                    detected_game_low1_fps = m.low_1pct_fps;
                } else {
                    // 부모 런처 프로세스가 잡힌 경우 동일 실행 파일명 또는 동일 게임명으로 매칭된 자식 렌더링 프로세스 탐색
                    for p in &procs {
                        let pid = p.pid().as_u32();
                        if let Some(m) = pid_fps_map.get(&pid) {
                            let pname = p.name().to_string_lossy();
                            let same_exe = pname.eq_ignore_ascii_case(&detected_game_exe);
                            let same_game = detect_game_from_process(&pname, p.exe(), &self.custom_games)
                                .map_or(false, |gm| gm.name == detected_game_name);
                            if same_exe || same_game {
                                detected_game_fps = m.fps;
                                detected_game_frame_ms = m.frame_ms;
                                detected_game_low1_fps = m.low_1pct_fps;
                                detected_game_pid = pid;
                               break;
                            }
                        }
                    }
                }
            }

            // 활성 게임 PID 상태 캐시 (게임 전환 및 종료 감지용)
            if !detected_game_name.is_empty() {
                self.active_game_pid = detected_game_pid;
                self.active_game_name = detected_game_name.clone();
                self.active_game_exe = detected_game_exe.clone();
                if let Ok(mut tgt) = self.active_game_target.lock() {
                    *tgt = (detected_game_pid, detected_game_name.clone());
                }
            } else {
                self.active_game_pid = 0;
                self.active_game_name.clear();
                self.active_game_exe.clear();
                if let Ok(mut tgt) = self.active_game_target.lock() {
                    *tgt = (0, String::new());
                }
            }

            let now = now_secs();
            let mut active_session_id = String::new();
            let mut active_duration_secs = 0u64;
            let session_sample_fps = if detected_game_fps > 0.0 {
                detected_game_fps
            } else {
                0.0
            };
            let session_sample_low1 = if detected_game_low1_fps > 0.0 {
                detected_game_low1_fps
            } else {
                session_sample_fps
            };

            if !detected_game_name.is_empty() {
                let est_start = if detected_game_start_ts > 0 && detected_game_start_ts <= now {
                    detected_game_start_ts
                } else {
                    now.saturating_sub(detected_game_run_secs)
                };
                let calc_run = detected_game_run_secs
                    .max(now.saturating_sub(est_start))
                    .max(1);

                let found_idx = self.game_sessions.iter().rposition(|s| {
                    s.game_name == detected_game_name
                        && ((s.pid == detected_game_pid && s.start_ts.abs_diff(est_start) <= 180)
                            || now.saturating_sub(s.end_ts) <= 30)
                });

                if let Some(idx) = found_idx {
                    let s = &mut self.game_sessions[idx];
                    s.pid = detected_game_pid;
                    s.end_ts = now;
                    let since_start = now.saturating_sub(s.start_ts).max(1);
                    s.duration_secs = s.duration_secs.max(calc_run).max(since_start);
                    s.max_cpu = s.max_cpu.max(detected_game_cpu);
                    s.max_mem_mb = s.max_mem_mb.max(detected_game_mem_mb);
                    s.max_gpu_temp = s.max_gpu_temp.max(gpu_data.temp_c);
                    s.max_gpu_usage = s.max_gpu_usage.max(gpu_data.usage_pct);
                    if session_sample_fps > 0.0 {
                        s.fps_samples = s.fps_samples.saturating_add(1);
                        let n = s.fps_samples as f32;
                        s.avg_fps = ((s.avg_fps * (n - 1.0)) + session_sample_fps) / n;
                        s.low_1pct_fps = if s.low_1pct_fps <= 0.0 {
                            session_sample_low1
                        } else {
                            s.low_1pct_fps * 0.85 + session_sample_low1 * 0.15
                        };
                    }
                    active_session_id = s.id.clone();
                    active_duration_secs = s.duration_secs;
                } else {
                    let id = format!("{}_{}", est_start, detected_game_pid);
                    active_session_id = id.clone();
                    active_duration_secs = calc_run;
                    let init_fps = session_sample_fps;
                    let init_low1 = session_sample_low1;
                    self.game_sessions.push(GameSessionRecord {
                        id,
                        game_name: detected_game_name.clone(),
                        exe_name: detected_game_exe.clone(),
                        pid: detected_game_pid,
                        start_ts: est_start,
                        end_ts: now,
                        duration_secs: calc_run,
                        max_cpu: detected_game_cpu,
                        max_mem_mb: detected_game_mem_mb,
                        avg_fps: init_fps,
                        low_1pct_fps: init_low1,
                        max_gpu_temp: gpu_data.temp_c,
                        max_gpu_usage: gpu_data.usage_pct,
                        fps_samples: if init_fps > 0.0 { 1 } else { 0 },
                    });
                    save_game_sessions(&self.game_sessions);
                    self.last_game_log_save = Instant::now();
                }

                if self.last_game_log_save.elapsed() >= Duration::from_secs(5) {
                    save_game_sessions(&self.game_sessions);
                    self.last_game_log_save = Instant::now();
                }
                self.was_game_active = true;
            } else if self.was_game_active {
                save_game_sessions(&self.game_sessions);
                self.was_game_active = false;
            }

            let proc_json: Vec<String> = procs
                .into_iter()
                .take(100)
                .map(|p| {
                    let name = json_escape(&p.name().to_string_lossy());
                    let mem_mb = p.memory() as f64 / 1_048_576.0;
                    let du = p.disk_usage();
                    let r_mbs = (du.read_bytes as f64 / dt_secs) / 1_048_576.0;
                    let w_mbs = (du.written_bytes as f64 / dt_secs) / 1_048_576.0;
                    format!(
                        r#"{{"pid":{},"name":"{}","cpu":{:.1},"mem_mb":{:.1},"run_secs":{},"disk_r_mb_s":{:.2},"disk_w_mb_s":{:.2}}}"#,
                        p.pid().as_u32(),
                        name,
                        p.cpu_usage(),
                        mem_mb,
                        p.run_time(),
                        r_mbs,
                        w_mbs
                    )
                })
                .collect();

            let game_logs_json: Vec<String> = self
                .game_sessions
                .iter()
                .rev()
                .take(250)
                .map(|s| {
                    let is_active = !active_session_id.is_empty() && s.id == active_session_id;
                    format!(
                        r#"{{"id":"{}","name":"{}","exe":"{}","pid":{},"start_ts":{},"end_ts":{},"duration_secs":{},"max_cpu":{:.1},"max_mem_mb":{:.1},"avg_fps":{:.1},"low_1pct_fps":{:.1},"max_gpu_temp":{:.1},"max_gpu_usage":{:.1},"active":{}}}"#,
                        json_escape(&s.id),
                        json_escape(&s.game_name),
                        json_escape(&s.exe_name),
                        s.pid,
                        s.start_ts,
                        s.end_ts,
                        s.duration_secs,
                        s.max_cpu,
                        s.max_mem_mb,
                        s.avg_fps,
                        s.low_1pct_fps,
                        s.max_gpu_temp,
                        s.max_gpu_usage,
                        is_active
                    )
                })
                .collect();

            let cpu_temp_val = self.cpu_temp.lock().ok().and_then(|t| *t);
            let cpu_temp_json = match cpu_temp_val {
                Some(v) => format!("{:.1}", v),
                None => "null".to_string(),
            };
            let gpu_temp_val = if gpu_data.temp_c > 0.0 {
                gpu_data.temp_c
            } else if let Some(ct) = cpu_temp_val {
                ct
            } else {
                0.0
            };

            self.cached_json = format!(
                r#"{{"cpu":{:.1},"cpu_temp_c":{},"cores":[{}],"total_mem":{},"used_mem":{},"total_swap":{},"used_swap":{},"uptime":{},"cpu_brand":"{}","os_name":"{}","user_name":"{}","startup_enabled":{},"theme":{{"is_light":{},"accent":"{}","accent_rgb":"{}"}},"gpu":{{"name":"{}","usage":{:.1},"vram_used_mb":{:.0},"vram_total_mb":{:.0},"temp_c":{:.1},"power_w":{:.1},"clock_mhz":{}}},"net":{{"rx_mb_s":{:.3},"tx_mb_s":{:.3},"rx_mbps":{:.2},"tx_mbps":{:.2},"rx_total_gb":{:.2},"tx_total_gb":{:.2},"iface":"{}","ping_ms":{:.1},"jitter_ms":{:.1},"online":{},"ping_target":"{}","is_game_ping":{},"game_server_ip":"{}","game_server_port":{},"interfaces":[{}]}},"disk_io":{{"read_mb_s":{:.2},"write_mb_s":{:.2}}},"disks":[{}],"game":{{"active":{},"name":"{}","exe":"{}","pid":{},"cpu":{:.1},"mem_mb":{:.1},"run_secs":{},"session_id":"{}","fps":{:.1},"frame_ms":{:.2},"low_1pct_fps":{:.1}}},"game_logs":[{}],"processes":[{}]}}"#,
                global_cpu,
                cpu_temp_json,
                cpus.join(","),
                total_mem,
                used_mem,
                total_swap,
                used_swap,
                uptime,
                cpu_brand,
                os_name,
                json_escape(&self.user_name),
                self.startup_enabled,
                theme_data.is_light,
                theme_data.accent_hex,
                theme_data.accent_rgb,
                json_escape(&gpu_data.name),
                gpu_data.usage_pct,
                gpu_data.vram_used_mb,
                gpu_data.vram_total_mb,
                gpu_temp_val,
                gpu_data.power_w,
                gpu_data.clock_mhz,
                net_rx_mb_s,
                net_tx_mb_s,
                net_rx_mbps,
                net_tx_mbps,
                net_rx_total_gb,
                net_tx_total_gb,
                json_escape(&active_iface),
                ping_data.ping_ms,
                ping_data.jitter_ms,
                ping_data.online,
                json_escape(&ping_data.target),
                ping_data.is_game_ping,
                json_escape(&ping_data.game_server_ip),
                ping_data.game_server_port,
                ifaces_json.join(","),
                disk_read_mb_s,
                disk_write_mb_s,
                disks_json.join(","),
                !detected_game_name.is_empty(),
                json_escape(&detected_game_name),
                json_escape(&detected_game_exe),
                detected_game_pid,
                detected_game_cpu,
                detected_game_mem_mb,
                active_duration_secs,
                json_escape(&active_session_id),
                detected_game_fps,
                detected_game_frame_ms,
                detected_game_low1_fps,
                game_logs_json.join(","),
                proc_json.join(",")
            );
        }
        &self.cached_json
    }
}

#[derive(Clone, Copy)]
struct WindowBounds {
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    has_pos: bool,
}

impl Default for WindowBounds {
    fn default() -> Self {
        Self {
            x: 120,
            y: 80,
            w: 1360,
            h: 880,
            has_pos: false,
        }
    }
}

fn persistent_config_dir() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let dir = std::path::PathBuf::from(local_app_data).join("CoreFlow");
        if std::fs::create_dir_all(&dir).is_ok() {
            return dir;
        }
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        let dir = std::path::PathBuf::from(home).join("Library/Application Support/CoreFlow");
        if std::fs::create_dir_all(&dir).is_ok() {
            return dir;
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.to_path_buf();
        }
    }
    std::env::temp_dir()
}

fn persistent_config_path(filename: &str) -> std::path::PathBuf {
    let primary = persistent_config_dir().join(filename);
    if !primary.exists() {
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let legacy = dir.join(filename);
                if legacy.exists() && legacy != primary {
                    let _ = std::fs::copy(&legacy, &primary);
                }
            }
        }
    }
    primary
}

fn write_persistent_config(filename: &str, bytes: &[u8]) -> bool {
    let primary = persistent_config_path(filename);
    let ok = std::fs::write(&primary, bytes).is_ok();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let legacy = dir.join(filename);
            if legacy != primary {
                let _ = std::fs::write(&legacy, bytes);
            }
        }
    }
    ok
}

fn bounds_file_path() -> std::path::PathBuf {
    persistent_config_path("rustcord_window_bounds.cfg")
}

fn theme_pref_file_path() -> std::path::PathBuf {
    persistent_config_path("rustcord_theme_pref.cfg")
}

fn load_theme_pref() -> String {
    let path = theme_pref_file_path();
    if let Ok(text) = std::fs::read_to_string(path) {
        let m = text.trim();
        if m == "light" || m == "dark" || m == "auto" {
            return m.to_string();
        }
    }
    "auto".to_string()
}

fn save_theme_pref(mode: &str) {
    let m = mode.trim();
    if m == "light" || m == "dark" || m == "auto" {
        let _ = write_persistent_config("rustcord_theme_pref.cfg", m.as_bytes());
    }
}

fn todos_file_path() -> std::path::PathBuf {
    persistent_config_path("coreflow_todos.json")
}

fn load_todos_json() -> String {
    let path = todos_file_path();
    if let Ok(text) = std::fs::read_to_string(path) {
        let trimmed = text.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            return trimmed.to_string();
        }
    }
    "[]".to_string()
}

fn save_todos_json(raw: &[u8]) -> bool {
    if raw.len() > 512 * 1024 {
        return false;
    }
    if let Ok(text) = std::str::from_utf8(raw) {
        let trimmed = text.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            return write_persistent_config("coreflow_todos.json", trimmed.as_bytes());
        }
    }
    false
}

fn alerts_file_path() -> std::path::PathBuf {
    persistent_config_path("coreflow_alerts.json")
}

fn load_alerts_json() -> String {
    let path = alerts_file_path();
    if let Ok(text) = std::fs::read_to_string(path) {
        let trimmed = text.trim();
        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            return trimmed.to_string();
        }
    }
    "null".to_string()
}

fn save_alerts_json(raw: &[u8]) -> bool {
    if raw.len() > 1024 * 1024 {
        return false;
    }
    if let Ok(text) = std::str::from_utf8(raw) {
        let trimmed = text.trim();
        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            return write_persistent_config("coreflow_alerts.json", trimmed.as_bytes());
        }
    }
    false
}

fn ui_prefs_file_path() -> std::path::PathBuf {
    persistent_config_path("coreflow_ui_prefs.json")
}

fn load_ui_prefs_json() -> String {
    let path = ui_prefs_file_path();
    if let Ok(text) = std::fs::read_to_string(path) {
        let trimmed = text.trim();
        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            return trimmed.to_string();
        }
    }
    "null".to_string()
}

fn save_ui_prefs_json(raw: &[u8]) -> bool {
    if raw.len() > 512 * 1024 {
        return false;
    }
    if let Ok(text) = std::str::from_utf8(raw) {
        let trimmed = text.trim();
        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            return write_persistent_config("coreflow_ui_prefs.json", trimmed.as_bytes());
        }
    }
    false
}

fn custom_games_file_path() -> std::path::PathBuf {
    persistent_config_path("coreflow_custom_games.json")
}

fn load_custom_games() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let path = custom_games_file_path();
    if let Ok(text) = std::fs::read_to_string(path) {
        let trimmed = text.trim();
        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            let inner = &trimmed[1..trimmed.len() - 1];
            for part in inner.split(',') {
                let kv: Vec<&str> = part.split(':').collect();
                if kv.len() == 2 {
                    let k = kv[0].trim().trim_matches('"').to_lowercase();
                    let v = kv[1].trim().trim_matches('"').to_string();
                    if !k.is_empty() && !v.is_empty() && !is_blacklisted_system_process(&k) && !is_non_game_window_title(&v) {
                        map.insert(k, v);
                    }
                }
            }
        }
    }
    map
}

fn save_custom_games(map: &std::collections::HashMap<String, String>) -> bool {
    let mut entries = Vec::new();
    for (k, v) in map {
        entries.push(format!("\"{}\":\"{}\"", json_escape(k), json_escape(v)));
    }
    let body = format!("{{{}}}", entries.join(","));
    write_persistent_config("coreflow_custom_games.json", body.as_bytes())
}

fn custom_avatar_path() -> std::path::PathBuf {
    persistent_config_path("rustcord_custom_avatar.img")
}

#[cfg(target_os = "windows")]
fn query_windows_user_name() -> String {
    if let Some(name) = reg_find_subkey_string(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData",
        "LoggedOnDisplayName",
    ) {
        return name;
    }

    std::env::var("USERNAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "Windows User".to_string())
}

#[cfg(not(target_os = "windows"))]
fn query_windows_user_name() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "Mac User".to_string())
}

#[cfg(target_os = "windows")]
fn query_startup_enabled() -> bool {
    reg_read_string(
        HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "CoreFlow",
    )
    .is_some()
}

#[cfg(target_os = "macos")]
fn query_startup_enabled() -> bool {
    if let Some(home) = std::env::var_os("HOME") {
        let plist_path = std::path::PathBuf::from(home)
            .join("Library/LaunchAgents/com.coreflow.app.plist");
        plist_path.exists()
    } else {
        false
    }
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn query_startup_enabled() -> bool {
    false
}

#[cfg(target_os = "windows")]
fn set_startup_enabled(enable: bool) -> bool {
    // 이전 이름(RustCordStudio) 레지스트리가 남아있다면 정리
    let _ = reg_delete_value(
        HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "RustCordStudio",
    );

    if enable {
        let Ok(exe) = std::env::current_exe() else {
            return false;
        };
        let quoted = format!("\"{}\"", exe.display());
        reg_write_string(
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "CoreFlow",
            &quoted,
        )
    } else {
        let _ = reg_delete_value(
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "CoreFlow",
        );
        true
    }
}

#[cfg(target_os = "macos")]
fn set_startup_enabled(enable: bool) -> bool {
    let Some(home) = std::env::var_os("HOME") else { return false; };
    let plist_path = std::path::PathBuf::from(home)
        .join("Library/LaunchAgents/com.coreflow.app.plist");
    if enable {
        let Ok(exe) = std::env::current_exe() else { return false; };
        let plist_content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.coreflow.app</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"#,
            exe.to_string_lossy()
        );
        if let Some(parent) = plist_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&plist_path, plist_content).is_ok()
    } else {
        let _ = std::fs::remove_file(&plist_path);
        true
    }
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn set_startup_enabled(_enable: bool) -> bool {
    true
}

fn is_valid_image_bytes(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x89, b'P', b'N', b'G'])
        || bytes.starts_with(&[0xFF, 0xD8, 0xFF])
        || bytes.starts_with(b"BM")
        || bytes.starts_with(b"GIF8")
        || (bytes.len() > 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP")
}

fn detect_image_mime(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        "image/png"
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        "image/jpeg"
    } else if bytes.starts_with(b"BM") {
        "image/bmp"
    } else if bytes.starts_with(b"GIF8") {
        "image/gif"
    } else if bytes.len() > 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        "image/webp"
    } else {
        "image/png"
    }
}

/// Windows .accountpicture-ms 바이너리 내부에서 가장 큰 JPEG 이미지를 추출
#[cfg(target_os = "windows")]
fn extract_jpeg_from_accountpicture(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut best: Option<&[u8]> = None;
    let mut i = 0usize;
    while i + 4 < bytes.len() {
        if bytes[i] == 0xFF && bytes[i + 1] == 0xD8 && bytes[i + 2] == 0xFF {
            let start = i;
            let mut end = None;
            let mut j = start + 3;
            while j + 1 < bytes.len() {
                if bytes[j] == 0xFF && bytes[j + 1] == 0xD9 {
                    end = Some(j + 2);
                    break;
                }
                j += 1;
            }
            if let Some(e) = end {
                let slice = &bytes[start..e];
                if slice.len() > 512 && best.map_or(true, |b| slice.len() > b.len()) {
                    best = Some(slice);
                }
                i = e;
                continue;
            }
        }
        i += 1;
    }
    best.map(|s| s.to_vec())
}

fn load_windows_avatar_bytes() -> (Vec<u8>, &'static str) {
    // 1. 사용자가 앱 내에서 직접 지정한 커스텀 프로필 사진이 있으면 최우선 반환
    let custom_path = custom_avatar_path();
    if let Ok(bytes) = std::fs::read(&custom_path) {
        if bytes.len() > 32 {
            let mime = detect_image_mime(&bytes);
            return (bytes, mime);
        }
    }

    #[cfg(target_os = "windows")]
    {
        // 2. Windows 레지스트리 AccountPicture\Users 에서 Image448 / Image192 / Image96 경로 탐색 (네이티브 Win32 API)
        for key_name in ["Image448", "Image192", "Image96", "Image1080", "Image64"] {
            if let Some(img_path) = reg_find_subkey_string(
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\AccountPicture\Users",
                key_name,
            ) {
                if let Ok(bytes) = std::fs::read(&img_path) {
                    if bytes.len() > 64 && is_valid_image_bytes(&bytes) {
                        let mime = detect_image_mime(&bytes);
                        return (bytes, mime);
                    }
                }
            }
        }

        // 3. %APPDATA%\Microsoft\Windows\AccountPictures 폴더에서 이미지 또는 .accountpicture-ms 추출
        if let Ok(appdata) = std::env::var("APPDATA") {
            let dir = std::path::PathBuf::from(appdata).join(r"Microsoft\Windows\AccountPictures");
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    let ext = p
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    if let Ok(bytes) = std::fs::read(&p) {
                        if ext == "accountpicture-ms" {
                            if let Some(jpg) = extract_jpeg_from_accountpicture(&bytes) {
                                return (jpg, "image/jpeg");
                            }
                        } else if matches!(ext.as_str(), "jpg" | "jpeg" | "png" | "bmp") && bytes.len() > 64 {
                            let mime = detect_image_mime(&bytes);
                            return (bytes, mime);
                        }
                    }
                }
            }
        }

        // 4. %TEMP%\{USERNAME}.bmp 또는 C:\ProgramData\Microsoft\User Account Pictures 기본 프로필 사진 확인
        if let Ok(username) = std::env::var("USERNAME") {
            let temp_bmp = std::env::temp_dir().join(format!("{username}.bmp"));
            if let Ok(bytes) = std::fs::read(temp_bmp) {
                if bytes.len() > 64 {
                    let mime = detect_image_mime(&bytes);
                    return (bytes, mime);
                }
            }
        }

        for default_win_pic in [
            r"C:\ProgramData\Microsoft\User Account Pictures\user-192.png",
            r"C:\ProgramData\Microsoft\User Account Pictures\user.png",
            r"C:\ProgramData\Microsoft\User Account Pictures\user-48.png",
            r"C:\ProgramData\Microsoft\User Account Pictures\user.bmp",
        ] {
            if let Ok(bytes) = std::fs::read(default_win_pic) {
                if bytes.len() > 64 {
                    let mime = detect_image_mime(&bytes);
                    return (bytes, mime);
                }
            }
        }
    }

    // 5. 파일이 없을 경우 깔끔한 기본 사용자 실루엣 SVG 제공
    let fallback_svg = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120"><rect width="120" height="120" rx="60" fill="#0078d4"/><circle cx="60" cy="44" r="22" fill="#ffffff"/><path d="M22 106c4-22 21-34 38-34s34 12 38 34" fill="#ffffff"/></svg>"##;
    (fallback_svg.as_bytes().to_vec(), "image/svg+xml")
}

#[derive(Clone, Debug)]
struct MiniHudState {
    is_mini: bool,
    wide: bool,
    topmost: bool,
    mini_x: i32,
    mini_y: i32,
    mini_w: i32,
    mini_h: i32,
    normal_x: i32,
    normal_y: i32,
    normal_w: i32,
    normal_h: i32,
}

impl Default for MiniHudState {
    fn default() -> Self {
        Self {
            is_mini: false,
            wide: false,
            topmost: true,
            mini_x: 0,
            mini_y: 0,
            mini_w: 450,
            mini_h: 265,
            normal_x: 120,
            normal_y: 80,
            normal_w: 1360,
            normal_h: 880,
        }
    }
}

fn minihud_state_file_path() -> std::path::PathBuf {
    persistent_config_path("coreflow_minihud_state.json")
}

fn load_minihud_state() -> MiniHudState {
    let path = minihud_state_file_path();
    let mut state = MiniHudState::default();
    let Ok(text) = std::fs::read_to_string(path) else {
        return state;
    };
    for line in text.lines() {
        let trimmed = line.trim().trim_matches(|c| c == '{' || c == '}' || c == ',');
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().trim_matches('"');
            let val = v.trim().trim_matches('"');
            match key {
                "is_mini" => state.is_mini = val == "true" || val == "1",
                "wide" => state.wide = val == "true" || val == "1",
                "topmost" => state.topmost = val != "false" && val != "0",
                "mini_x" => if let Ok(n) = val.parse::<i32>() { state.mini_x = n; },
                "mini_y" => if let Ok(n) = val.parse::<i32>() { state.mini_y = n; },
                "mini_w" => if let Ok(n) = val.parse::<i32>() { if n >= 200 { state.mini_w = n; } },
                "mini_h" => if let Ok(n) = val.parse::<i32>() { if n >= 100 { state.mini_h = n; } },
                "normal_x" => if let Ok(n) = val.parse::<i32>() { state.normal_x = n; },
                "normal_y" => if let Ok(n) = val.parse::<i32>() { state.normal_y = n; },
                // 일반 창 크기는 최소 900x550 이상일 때만 유효한 일반 창 크기로 인정 (미니 HUD 크기로 덮어씌워지는 현상 원천 차단)
                "normal_w" => if let Ok(n) = val.parse::<i32>() { if n >= 900 { state.normal_w = n; } },
                "normal_h" => if let Ok(n) = val.parse::<i32>() { if n >= 550 { state.normal_h = n; } },
                _ => {}
            }
        }
    }
    state
}

fn save_minihud_state(s: &MiniHudState) {
    let nw = if s.normal_w >= 900 { s.normal_w } else { 1360 };
    let nh = if s.normal_h >= 550 { s.normal_h } else { 880 };
    let json = format!(
        "{{\n  \"is_mini\": {},\n  \"wide\": {},\n  \"topmost\": {},\n  \"mini_x\": {},\n  \"mini_y\": {},\n  \"mini_w\": {},\n  \"mini_h\": {},\n  \"normal_x\": {},\n  \"normal_y\": {},\n  \"normal_w\": {},\n  \"normal_h\": {}\n}}",
        s.is_mini, s.wide, s.topmost, s.mini_x, s.mini_y, s.mini_w, s.mini_h,
        s.normal_x, s.normal_y, nw, nh
    );
    let _ = write_persistent_config("coreflow_minihud_state.json", json.as_bytes());
}

fn load_window_bounds() -> WindowBounds {
    let path = bounds_file_path();
    if let Ok(text) = std::fs::read_to_string(path) {
        let parts: Vec<&str> = text.trim().split(',').collect();
        if parts.len() == 4 {
            if let (Ok(x), Ok(y), Ok(w), Ok(h)) = (
                parts[0].parse::<i32>(),
                parts[1].parse::<i32>(),
                parts[2].parse::<i32>(),
                parts[3].parse::<i32>(),
            ) {
                if x > -10000 && y > -10000 && w >= 900 && h >= 550 {
                    return WindowBounds {
                        x,
                        y,
                        w,
                        h,
                        has_pos: true,
                    };
                }
            }
        }
    }
    WindowBounds::default()
}

fn save_window_bounds(x: i32, y: i32, w: i32, h: i32) {
    // 최소화 상태(-32000)나 미니 HUD 크기(900x550 미만)는 일반 창 크기로 저장하지 않음
    if x <= -10000 || y <= -10000 || w < 900 || h < 550 {
        return;
    }
    let _ = write_persistent_config("rustcord_window_bounds.cfg", format!("{x},{y},{w},{h}").as_bytes());
}

fn parse_query_bounds(first_line: &str) {
    // 예: GET /api/stats?x=100&y=200&w=1360&h=880 HTTP/1.1
    let path_part = first_line.split_whitespace().nth(1).unwrap_or("");
    if let Some(q_idx) = path_part.find('?') {
        let query = &path_part[q_idx + 1..];
        let mut x = None;
        let mut y = None;
        let mut w = None;
        let mut h = None;
        let mut is_mini = false;
        for pair in query.split('&') {
            let mut kv = pair.splitn(2, '=');
            let k = kv.next().unwrap_or("");
            let v = kv.next().unwrap_or("");
            match k {
                "x" => x = v.parse::<i32>().ok(),
                "y" => y = v.parse::<i32>().ok(),
                "w" => w = v.parse::<i32>().ok(),
                "h" => h = v.parse::<i32>().ok(),
                "mini" => is_mini = v == "1" || v == "true",
                "mode" => save_theme_pref(v),
                _ => {}
            }
        }
        if !is_mini {
            if let (Some(xv), Some(yv), Some(wv), Some(hv)) = (x, y, w, h) {
                if wv >= 900 && hv >= 550 {
                    save_window_bounds(xv, yv, wv, hv);
                    let mut ms = load_minihud_state();
                    if !ms.is_mini {
                        ms.normal_x = xv;
                        ms.normal_y = yv;
                        ms.normal_w = wv;
                        ms.normal_h = hv;
                        save_minihud_state(&ms);
                    }
                }
            }
        } else if let (Some(xv), Some(yv)) = (x, y) {
            if xv > -10000 && yv > -10000 {
                let mut ms = load_minihud_state();
                ms.is_mini = true;
                ms.mini_x = xv;
                ms.mini_y = yv;
                if let Some(wv) = w { if (200..900).contains(&wv) { ms.mini_w = wv; } }
                if let Some(hv) = h { if (100..550).contains(&hv) { ms.mini_h = hv; } }
                save_minihud_state(&ms);
            }
        }
    }
}

fn launch_desktop_window(url: &str) {
    let bounds = load_window_bounds();
    let mini_state = load_minihud_state();
    let profile_dir = std::env::temp_dir().join("rustcord_app_profile");

    let (win_w, win_h, win_x, win_y, has_pos) = if mini_state.is_mini {
        let w = if mini_state.mini_w >= 220 { mini_state.mini_w } else if mini_state.wide { 760 } else { 450 };
        let h = if mini_state.mini_h >= 100 { mini_state.mini_h } else if mini_state.wide { 168 } else { 265 };
        let has_p = mini_state.mini_x > -10000 && mini_state.mini_y > -10000 && (mini_state.mini_x != 0 || mini_state.mini_y != 0);
        (w, h, mini_state.mini_x, mini_state.mini_y, has_p)
    } else {
        (bounds.w, bounds.h, bounds.x, bounds.y, bounds.has_pos)
    };

    let launch_url = if mini_state.is_mini {
        format!("{url}?mini=1")
    } else {
        url.to_string()
    };

    #[cfg(target_os = "windows")]
    {
        let edge_paths = [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ];

        for path in edge_paths {
            if std::path::Path::new(path).exists() {
                let mut cmd = Command::new(path);
                cmd.arg(format!("--app={launch_url}"))
                    .arg(format!("--user-data-dir={}", profile_dir.display()))
                    .arg(format!("--window-size={win_w},{win_h}"))
                    .arg("--new-window")
                    // 최소화/백그라운드 상태에서도 타이머·렌더러가 멈추지 않도록 절전(스로틀링) 비활성화
                    .arg("--disable-background-timer-throttling")
                    .arg("--disable-renderer-backgrounding")
                    .arg("--disable-backgrounding-occluded-windows")
                    .arg("--disable-features=IntensiveWakeUpThrottling,CalculateNativeWinOcclusion");

                if has_pos {
                    cmd.arg(format!("--window-position={win_x},{win_y}"));
                }

                let _ = cmd.spawn();
                return;
            }
        }

        let _ = Command::new("explorer.exe").arg(&launch_url).spawn();
    }

    #[cfg(target_os = "macos")]
    {
        let mac_browsers = [
            "/Applications/Google Chrome.app",
            "/Applications/Microsoft Edge.app",
            "/Applications/Brave Browser.app",
            "/Applications/Arc.app",
        ];
        for app in mac_browsers {
            if std::path::Path::new(app).exists() {
                let _ = Command::new("open")
                    .args([
                        "-na",
                        app,
                        "--args",
                        &format!("--app={launch_url}"),
                        &format!("--user-data-dir={}", profile_dir.display()),
                        &format!("--window-size={win_w},{win_h}"),
                        "--new-window",
                    ])
                    .spawn();
                return;
            }
        }
        let _ = Command::new("open").arg(&launch_url).spawn();
    }

    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let _ = Command::new("xdg-open").arg(&launch_url).spawn();
    }
}

/// 실행된 CoreFlow 앱 창의 타이틀바 및 작업 표시줄 아이콘을 내장 리소스 아이콘(ID 1)으로 즉시 동기화
#[cfg(target_os = "windows")]
fn spawn_window_icon_applier() {
    thread::spawn(|| {
        const IMAGE_ICON: u32 = 1;
        const WM_SETICON: u32 = 0x0080;
        const ICON_SMALL: usize = 0;
        const ICON_BIG: usize = 1;

        let hmod = unsafe { GetModuleHandleW(std::ptr::null()) };
        if hmod == 0 {
            return;
        }
        let hicon_big = unsafe { LoadImageW(hmod, 1usize as *const u16, IMAGE_ICON, 256, 256, 0) };
        let hicon_small = unsafe { LoadImageW(hmod, 1usize as *const u16, IMAGE_ICON, 16, 16, 0) };
        if hicon_big == 0 && hicon_small == 0 {
            return;
        }

        for _ in 0..30 {
            thread::sleep(Duration::from_millis(350));
            let hwnd = find_app_window();
            if hwnd != 0 {
                unsafe {
                    if hicon_big != 0 {
                        SendMessageW(hwnd, WM_SETICON, ICON_BIG, hicon_big);
                    }
                    if hicon_small != 0 {
                        SendMessageW(hwnd, WM_SETICON, ICON_SMALL, hicon_small);
                    }
                }
                // 미니 HUD 모드로 실행된 경우 최상위(Topmost) 속성 및 크기 강제 동기화
                let mini_state = load_minihud_state();
                if mini_state.is_mini {
                    let w = if mini_state.mini_w >= 220 { mini_state.mini_w } else if mini_state.wide { 760 } else { 450 };
                    let h = if mini_state.mini_h >= 100 { mini_state.mini_h } else if mini_state.wide { 168 } else { 265 };
                    control_app_window(
                        Some(mini_state.topmost),
                        if mini_state.mini_x > -10000 && mini_state.mini_y > -10000 && (mini_state.mini_x != 0 || mini_state.mini_y != 0) { Some(mini_state.mini_x) } else { None },
                        if mini_state.mini_x > -10000 && mini_state.mini_y > -10000 && (mini_state.mini_x != 0 || mini_state.mini_y != 0) { Some(mini_state.mini_y) } else { None },
                        Some(w),
                        Some(h),
                    );
                }
                break;
            }
        }
    });
}

#[cfg(not(target_os = "windows"))]
fn spawn_window_icon_applier() {}

fn parse_query_i32(first_line: &str, key: &str) -> Option<i32> {
    parse_query_str(first_line, key)?.parse::<i32>().ok()
}

/// 컴팩트 미니 HUD 전환 시 Win32 SetWindowPos로 창 항상 위(Topmost) 고정 및 창 크기/위치를 즉시 제어
#[cfg(target_os = "windows")]
fn control_app_window(
    topmost: Option<bool>,
    x: Option<i32>,
    y: Option<i32>,
    w: Option<i32>,
    h: Option<i32>,
) -> bool {
    const HWND_TOPMOST: isize = -1;
    const HWND_NOTOPMOST: isize = -2;
    const SWP_NOSIZE: u32 = 0x0001;
    const SWP_NOMOVE: u32 = 0x0002;
    const SWP_NOZORDER: u32 = 0x0004;
    const SWP_SHOWWINDOW: u32 = 0x0040;
    const SW_RESTORE: i32 = 9;

    let hwnd = find_app_window();
    if hwnd == 0 {
        return false;
    }

    if w.is_some() && h.is_some() {
        unsafe {
            if IsZoomed(hwnd) != 0 || IsIconic(hwnd) != 0 {
                ShowWindow(hwnd, SW_RESTORE);
            }
        }
    }

    let mut flags = SWP_SHOWWINDOW;
    let insert_after = match topmost {
        Some(true) => HWND_TOPMOST,
        Some(false) => HWND_NOTOPMOST,
        None => {
            flags |= SWP_NOZORDER;
            0
        }
    };

    let (px, py) = match (x, y) {
        (Some(xv), Some(yv)) if xv > -10000 && yv > -10000 => (xv, yv),
        _ => {
            flags |= SWP_NOMOVE;
            (0, 0)
        }
    };

    let (pw, ph) = match (w, h) {
        (Some(wv), Some(hv)) if wv >= 220 && hv >= 110 => (wv, hv),
        _ => {
            flags |= SWP_NOSIZE;
            (0, 0)
        }
    };

    unsafe { SetWindowPos(hwnd, insert_after, px, py, pw, ph, flags) != 0 }
}

#[cfg(not(target_os = "windows"))]
fn control_app_window(
    _topmost: Option<bool>,
    _x: Option<i32>,
    _y: Option<i32>,
    _w: Option<i32>,
    _h: Option<i32>,
) -> bool {
    true
}

fn kill_process_by_pid(state: &Arc<Mutex<SharedState>>, pid: u32) -> bool {
    // 시스템 핵심 프로세스(PID <= 4) 및 자기 자신 종료 방지
    if pid <= 4 || pid == std::process::id() {
        return false;
    }
    let mut killed = false;
    if let Ok(mut guard) = state.lock() {
        if let Some(proc) = guard.sys.process(sysinfo::Pid::from_u32(pid)) {
            killed = proc.kill();
        }
        guard.last_refresh = Instant::now() - Duration::from_secs(2);
    }
    killed
}

fn url_decode(s: &str) -> String {
    let mut bytes = Vec::with_capacity(s.len());
    let raw = s.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' && i + 2 < raw.len() {
            if let (Some(h), Some(l)) = (
                (raw[i + 1] as char).to_digit(16),
                (raw[i + 2] as char).to_digit(16),
            ) {
                bytes.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        } else if raw[i] == b'+' {
            bytes.push(b' ');
            i += 1;
            continue;
        }
        bytes.push(raw[i]);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn parse_query_str(first_line: &str, key: &str) -> Option<String> {
    let path_part = first_line.split_whitespace().nth(1)?;
    let q_idx = path_part.find('?')?;
    let query = &path_part[q_idx + 1..];
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        let k = kv.next().unwrap_or("");
        let v = kv.next().unwrap_or("");
        if k == key {
            return Some(v.to_string());
        }
    }
    None
}

fn parse_query_u32(first_line: &str, key: &str) -> Option<u32> {
    parse_query_str(first_line, key)?.parse::<u32>().ok()
}

fn sanitize_filename(raw: &str) -> String {
    // 경로 탐색(Path Traversal: .., /, \) 차단 및 안전한 파일명 길이 제한
    let base_only = raw
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .replace("..", "_");
    let filtered: String = base_only
        .chars()
        .take(80)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = filtered.trim_matches('.').to_string();
    if trimmed.is_empty() {
        format!("monitoring_{}.csv", now_secs())
    } else if trimmed.ends_with(".csv") {
        trimmed
    } else {
        format!("{trimmed}.csv")
    }
}

fn read_full_http_body(stream: &mut TcpStream, initial_buf: &[u8]) -> Vec<u8> {
    let header_end = initial_buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4);

    let Some(body_start) = header_end else {
        return Vec::new();
    };

    let header_str = String::from_utf8_lossy(&initial_buf[..body_start]);
    let mut content_len = 0usize;
    for line in header_str.lines() {
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            if let Ok(len) = rest.trim().parse::<usize>() {
                content_len = len.min(MAX_HTTP_BODY_BYTES);
            }
        }
    }

    let initial_body = &initial_buf[body_start..];
    if initial_body.len() > MAX_HTTP_BODY_BYTES {
        return Vec::new();
    }

    let mut body = Vec::with_capacity(content_len.max(initial_body.len()));
    body.extend_from_slice(initial_body);

    let mut chunk = [0u8; 8192];
    while body.len() < content_len && body.len() < MAX_HTTP_BODY_BYTES {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let remain = MAX_HTTP_BODY_BYTES.saturating_sub(body.len());
                body.extend_from_slice(&chunk[..n.min(remain)]);
            }
            Err(_) => break,
        }
    }
    body
}

fn get_logs_dir() -> std::path::PathBuf {
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        let dir = std::path::PathBuf::from(home).join("Library/Logs/CoreFlow");
        let _ = std::fs::create_dir_all(&dir);
        return dir;
    }
    let base = persistent_config_dir();
    let logs = base.join("logs");
    let _ = std::fs::create_dir_all(&logs);
    logs
}

/// 로컬 HTTP API 요청의 세션 토큰 및 Origin/Host 검증 (CSRF 및 외부 웹페이지 공격 차단)
fn verify_api_request(req_headers: &str, first_line: &str, expected_token: &str) -> bool {
    let mut header_token_ok = false;
    for line in req_headers.lines().skip(1) {
        if line.trim().is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(host) = lower.strip_prefix("host:") {
            let h = host.trim();
            if !h.starts_with("127.0.0.1:") && h != "127.0.0.1" && !h.starts_with("localhost:") {
                return false;
            }
        }
        if let Some(origin) = lower.strip_prefix("origin:") {
            let o = origin.trim();
            if o != "null"
                && !o.starts_with("http://127.0.0.1:")
                && !o.starts_with("http://localhost:")
            {
                return false;
            }
        }
        if let Some(tok) = lower.strip_prefix("x-coreflow-token:") {
            if tok.trim() == expected_token {
                header_token_ok = true;
            }
        }
    }
    if header_token_ok {
        return true;
    }
    if let Some(q_tok) = parse_query_str(first_line, "token") {
        if q_tok == expected_token {
            return true;
        }
    }
    false
}

fn handle_client(
    mut stream: TcpStream,
    state: &Arc<Mutex<SharedState>>,
    last_heartbeat: &Arc<AtomicU64>,
    client_connected: &Arc<AtomicBool>,
    session_token: &str,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(4)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let mut buf = [0u8; 8192];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let req = String::from_utf8_lossy(&buf[..n]);
    let first_line = req.lines().next().unwrap_or("").to_string();

    // API 엔드포인트(/api/*)는(단순 이미지 조회 GET /api/avatar, GET /api/proc_icon 제외) 세션 토큰 검증 필수
    let is_api_call = first_line.contains(" /api/")
        && !first_line.starts_with("GET /api/avatar")
        && !first_line.starts_with("GET /api/proc_icon");
    if is_api_call && !verify_api_request(&req, &first_line, session_token) {
        let resp = "HTTP/1.1 403 Forbidden\r\nX-Content-Type-Options: nosniff\r\nContent-Length: 9\r\nConnection: close\r\n\r\nForbidden";
        let _ = stream.write_all(resp.as_bytes());
        return;
    }

    last_heartbeat.store(now_secs(), Ordering::SeqCst);
    client_connected.store(true, Ordering::SeqCst);
    if first_line.starts_with("GET /api/stats") || first_line.starts_with("POST /api/quit") || first_line.starts_with("GET /api/quit") {
        parse_query_bounds(&first_line);
    }

    if first_line.starts_with("GET /api/stats") {
        let target_param = parse_query_str(&first_line, "target").map(|v| url_decode(&v));
        let fps_param = parse_query_str(&first_line, "fps").and_then(|v| v.parse::<f32>().ok());
        let low1_param = parse_query_str(&first_line, "low1").and_then(|v| v.parse::<f32>().ok());
        let body = {
            let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(fps_v) = fps_param {
                if (0.0..=1000.0).contains(&fps_v) {
                    guard.client_fps = fps_v;
                }
            }
            if let Some(low1_v) = low1_param {
                if (0.0..=1000.0).contains(&low1_v) {
                    guard.client_low1_fps = low1_v;
                }
            }
            if let Some(t) = target_param {
                if !t.is_empty() && guard.target_proc != t {
                    guard.target_proc = t;
                    guard.last_refresh = Instant::now() - Duration::from_secs(2);
                }
            }
            guard.refresh_if_needed().to_string()
        };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/delete_game_log") {
        let id_arg = parse_query_str(&first_line, "id")
            .map(|v| url_decode(&v))
            .unwrap_or_default();
        if let Ok(mut guard) = state.lock() {
            if id_arg == "all" {
                guard.game_sessions.clear();
            } else if !id_arg.is_empty() {
                guard.game_sessions.retain(|s| s.id != id_arg);
            }
            save_game_sessions(&guard.game_sessions);
            guard.last_refresh = Instant::now() - Duration::from_secs(2);
        }
        let body = r#"{"ok":true}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/kill") {
        let ok = if let Some(pid) = parse_query_u32(&first_line, "pid") {
            kill_process_by_pid(state, pid)
        } else {
            false
        };
        let body = if ok {
            r#"{"ok":true}"#
        } else {
            r#"{"ok":false}"#
        };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/save_record") {
        let raw_name = parse_query_str(&first_line, "name").unwrap_or_default();
        let file_name = sanitize_filename(&raw_name);
        let body_bytes = read_full_http_body(&mut stream, &buf[..n]);
        let logs_dir = get_logs_dir();
        let file_path = logs_dir.join(&file_name);

        let mut file_content = Vec::with_capacity(3 + body_bytes.len());
        // UTF-8 BOM 추가 (엑셀에서 한글 깨짐 방지)
        file_content.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
        file_content.extend_from_slice(&body_bytes);

        let ok = std::fs::write(&file_path, &file_content).is_ok();
        let full_path_str = file_path.to_string_lossy().replace('\\', "/");
        let resp_json = if ok {
            format!(
                r#"{{"ok":true,"path":"{}","name":"{}"}}"#,
                json_escape(&full_path_str),
                json_escape(&file_name)
            )
        } else {
            r#"{"ok":false}"#.to_string()
        };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            resp_json.len(),
            resp_json
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/open_logs") {
        let logs_dir = get_logs_dir();
        let _ = Command::new("explorer.exe").arg(&logs_dir).spawn();
        let body = r#"{"ok":true}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("GET /favicon.ico")
        || first_line.starts_with("GET /api/icon.ico")
    {
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: image/x-icon\r\nX-Content-Type-Options: nosniff\r\nCache-Control: public, max-age=86400\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            APP_ICON_ICO.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(APP_ICON_ICO);
    } else if first_line.starts_with("GET /api/proc_icon") {
        let exe_name = parse_query_str(&first_line, "name")
            .map(|v| url_decode(&v))
            .unwrap_or_default();
        if let Some(ico_bytes) = resolve_and_get_proc_icon(&exe_name) {
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: image/x-icon\r\nX-Content-Type-Options: nosniff\r\nCache-Control: public, max-age=86400\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                ico_bytes.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&ico_bytes);
        } else {
            let svg = DEFAULT_PROC_ICON_SVG.as_bytes();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nCache-Control: public, max-age=86400\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                svg.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(svg);
        }
    } else if first_line.starts_with("GET /api/avatar") {
        let (img_bytes, mime) = load_windows_avatar_bytes();
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            mime,
            img_bytes.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(&img_bytes);
    } else if first_line.starts_with("POST /api/avatar") {
        let reset = parse_query_str(&first_line, "reset").unwrap_or_default() == "1";
        let path = custom_avatar_path();
        let ok = if reset {
            let _ = std::fs::remove_file(&path);
            true
        } else {
            let body_bytes = read_full_http_body(&mut stream, &buf[..n]);
            // 이미지 매직 바이트 및 크기(최대 8MB) 엄격 검증
            if body_bytes.len() > 32
                && body_bytes.len() <= 8 * 1024 * 1024
                && is_valid_image_bytes(&body_bytes)
            {
                std::fs::write(&path, &body_bytes).is_ok()
            } else {
                false
            }
        };
        let body = if ok { r#"{"ok":true}"# } else { r#"{"ok":false}"# };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/startup") {
        let enable_arg = parse_query_str(&first_line, "enable").unwrap_or_default();
        let enable = enable_arg == "1" || enable_arg == "true";
        let ok = set_startup_enabled(enable);
        let current = query_startup_enabled();
        if let Ok(mut guard) = state.lock() {
            guard.startup_enabled = current;
            guard.last_refresh = Instant::now() - Duration::from_secs(2);
        }
        let body = format!(r#"{{"ok":{},"enabled":{}}}"#, ok, current);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/window_ctl") {
        let topmost = parse_query_str(&first_line, "topmost").map(|v| v == "1" || v == "true");
        let x = parse_query_i32(&first_line, "x");
        let y = parse_query_i32(&first_line, "y");
        let w = parse_query_i32(&first_line, "w");
        let h = parse_query_i32(&first_line, "h");
        let ok = control_app_window(topmost, x, y, w, h);
        let body = if ok { r#"{"ok":true}"# } else { r#"{"ok":false}"# };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/minihud_state") {
        let is_mini = parse_query_str(&first_line, "mini").map(|v| v == "1" || v == "true").unwrap_or(false);
        let wide = parse_query_str(&first_line, "wide").map(|v| v == "1" || v == "true").unwrap_or(false);
        let topmost = parse_query_str(&first_line, "topmost").map(|v| v != "0" && v != "false").unwrap_or(true);
        let mut ms = load_minihud_state();
        ms.is_mini = is_mini;
        ms.wide = wide;
        ms.topmost = topmost;
        if let Some(mx) = parse_query_i32(&first_line, "mx") { ms.mini_x = mx; }
        if let Some(my) = parse_query_i32(&first_line, "my") { ms.mini_y = my; }
        if let Some(mw) = parse_query_i32(&first_line, "mw") { if mw >= 200 { ms.mini_w = mw; } }
        if let Some(mh) = parse_query_i32(&first_line, "mh") { if mh >= 100 { ms.mini_h = mh; } }
        if let Some(nx) = parse_query_i32(&first_line, "nx") { ms.normal_x = nx; }
        if let Some(ny) = parse_query_i32(&first_line, "ny") { ms.normal_y = ny; }
        if let Some(nw) = parse_query_i32(&first_line, "nw") { if nw >= 900 { ms.normal_w = nw; } }
        if let Some(nh) = parse_query_i32(&first_line, "nh") { if nh >= 550 { ms.normal_h = nh; } }
        save_minihud_state(&ms);
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}";
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("GET /api/minihud_state") {
        let ms = load_minihud_state();
        let body = format!(
            "{{\"ok\":true,\"is_mini\":{},\"wide\":{},\"topmost\":{},\"mini_x\":{},\"mini_y\":{},\"mini_w\":{},\"mini_h\":{},\"normal_x\":{},\"normal_y\":{},\"normal_w\":{},\"normal_h\":{}}}",
            ms.is_mini, ms.wide, ms.topmost, ms.mini_x, ms.mini_y, ms.mini_w, ms.mini_h,
            ms.normal_x, ms.normal_y, ms.normal_w, ms.normal_h
        );
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/todos") {
        let body_bytes = read_full_http_body(&mut stream, &buf[..n]);
        let ok = save_todos_json(&body_bytes);
        let body = if ok { r#"{"ok":true}"# } else { r#"{"ok":false}"# };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("GET /api/game_scan") {
        let (fg_pid, fg_title) = get_foreground_window_info().unwrap_or((0, String::new()));
        let pid_fps_map = query_all_active_pid_fps();
        let resp_json = {
            let guard = state.lock().unwrap_or_else(|e| e.into_inner());
            
            struct Candidate {
                pid: u32,
                name: String,
                title: String,
                cpu: f32,
                mem_mb: f64,
                reason: String,
                is_foreground: bool,
                is_custom: bool,
                score: u32,
            }

            let mut candidates = Vec::new();
            for p in guard.sys.processes().values() {
                let pname_raw = p.name().to_string_lossy();
                let exe_lower = pname_raw.to_lowercase();
                if is_blacklisted_system_process(&exe_lower) {
                    continue;
                }
                if let Some(pe) = p.exe() {
                    if is_ignored_game_path(&pe.to_string_lossy()) {
                        continue;
                    }
                }

                let pid = p.pid().as_u32();
                let is_fg = pid == fg_pid;
                let cpu = p.cpu_usage();
                let mem_mb = p.memory() as f64 / 1_048_576.0;
                let live_fps = pid_fps_map.get(&pid).map(|m| m.fps).unwrap_or(0.0);

                let m = detect_game_from_process(&pname_raw, p.exe(), &guard.custom_games);
                if let Some(matched) = m {
                    let mut score = match matched.confidence {
                        "custom" => 100,
                        "known" => 95,
                        "path" => 90,
                        "engine" => 75,
                        _ => 60,
                    };
                    let reason = if live_fps >= 1.0 {
                        score += 50;
                        format!("{} • DXGI {:.0} FPS 렌더링 중", matched.reason, live_fps)
                    } else {
                        matched.reason
                    };
                    candidates.push(Candidate {
                        pid,
                        name: pname_raw.into_owned(),
                        title: matched.name,
                        cpu,
                        mem_mb,
                        reason,
                        is_foreground: is_fg,
                        is_custom: matched.confidence == "custom",
                        score,
                    });
                } else if live_fps >= 10.0 && mem_mb > 120.0 {
                    let pname_str = pname_raw.to_string();
                    let title = if is_fg && !fg_title.is_empty() && !is_non_game_window_title(&fg_title) {
                        fg_title.clone()
                    } else {
                        pname_str.clone()
                    };
                    candidates.push(Candidate {
                        pid,
                        name: pname_str,
                        title,
                        cpu,
                        mem_mb,
                        reason: format!("실시간 DirectX/DXGI 화면 렌더링 감지 ({live_fps:.0} FPS)"),
                        is_foreground: is_fg,
                        is_custom: false,
                        score: 92,
                    });
                } else if is_fg && !fg_title.is_empty() && !is_non_game_window_title(&fg_title) && (mem_mb > 150.0 || cpu > 0.5) {
                    candidates.push(Candidate {
                        pid,
                        name: pname_raw.into_owned(),
                        title: fg_title.clone(),
                        cpu,
                        mem_mb,
                        reason: "현재 전면(포그라운드) 활성 창".to_string(),
                        is_foreground: true,
                        is_custom: false,
                        score: 85,
                    });
                } else if mem_mb > 400.0 && cpu > 1.0 {
                    let pname_str = pname_raw.to_string();
                    candidates.push(Candidate {
                        pid,
                        name: pname_str.clone(),
                        title: pname_str,
                        cpu,
                        mem_mb,
                        reason: format!("대용량 메모리 점유 프로세스 ({mem_mb:.0} MB)"),
                        is_foreground: is_fg,
                        is_custom: false,
                        score: 40,
                    });
                }
            }

            candidates.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| b.mem_mb.partial_cmp(&a.mem_mb).unwrap_or(std::cmp::Ordering::Equal)));

            let c_json: Vec<String> = candidates.into_iter().take(30).map(|c| {
                format!(
                    r#"{{"pid":{},"name":"{}","title":"{}","cpu":{:.1},"mem_mb":{:.1},"reason":"{}","is_foreground":{},"is_custom":{}}}"#,
                    c.pid,
                    json_escape(&c.name),
                    json_escape(&c.title),
                    c.cpu,
                    c.mem_mb,
                    json_escape(&c.reason),
                    c.is_foreground,
                    c.is_custom
                )
            }).collect();

            let custom_list: Vec<String> = guard.custom_games.iter().map(|(k, v)| {
                format!(r#"{{"exe":"{}","name":"{}"}}"#, json_escape(k), json_escape(v))
            }).collect();

            format!(
                r#"{{"ok":true,"current_target":"{}","active_game":{{"name":"{}","exe":"{}","pid":{}}},"candidates":[{}],"custom_games":[{}]}}"#,
                json_escape(&guard.target_proc),
                json_escape(&guard.active_game_name),
                json_escape(&guard.active_game_exe),
                guard.active_game_pid,
                c_json.join(","),
                custom_list.join(",")
            )
        };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            resp_json.len(),
            resp_json
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/custom_game") {
        let exe = parse_query_str(&first_line, "exe").map(|v| url_decode(&v)).unwrap_or_default().to_lowercase();
        let name = parse_query_str(&first_line, "name").map(|v| url_decode(&v)).unwrap_or_default();
        let ok = if !exe.is_empty() && !name.is_empty() && !is_blacklisted_system_process(&exe) && !is_non_game_window_title(&name) {
            if let Ok(mut guard) = state.lock() {
                guard.custom_games.insert(exe, name);
                save_custom_games(&guard.custom_games);
                guard.last_refresh = Instant::now() - Duration::from_secs(2);
                true
            } else {
                false
            }
        } else {
            false
        };
        let body = if ok { r#"{"ok":true}"# } else { r#"{"ok":false}"# };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/delete_custom_game") {
        let exe = parse_query_str(&first_line, "exe").map(|v| url_decode(&v)).unwrap_or_default().to_lowercase();
        let ok = if !exe.is_empty() {
            if let Ok(mut guard) = state.lock() {
                guard.custom_games.remove(&exe);
                save_custom_games(&guard.custom_games);
                guard.last_refresh = Instant::now() - Duration::from_secs(2);
                true
            } else {
                false
            }
        } else {
            false
        };
        let body = if ok { r#"{"ok":true}"# } else { r#"{"ok":false}"# };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/alerts") {
        let body_bytes = read_full_http_body(&mut stream, &buf[..n]);
        let ok = save_alerts_json(&body_bytes);
        let body = if ok { r#"{"ok":true}"# } else { r#"{"ok":false}"# };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/ui_prefs") {
        let body_bytes = read_full_http_body(&mut stream, &buf[..n]);
        let ok = save_ui_prefs_json(&body_bytes);
        let body = if ok { r#"{"ok":true}"# } else { r#"{"ok":false}"# };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("GET /api/check_update") {
        let json = check_github_update();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/perform_update") {
        let dl_url = parse_query_str(&first_line, "url")
            .map(|v| url_decode(&v))
            .unwrap_or_default();
        let json = perform_github_self_update(&dl_url, state);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/open_external") {
        let ext_url = parse_query_str(&first_line, "url")
            .map(|v| url_decode(&v))
            .unwrap_or_default();
        if ext_url.starts_with("https://github.com/neverloselkb/coreFlow") {
            #[cfg(target_os = "windows")]
            let _ = Command::new("cmd")
                .args(["/C", "start", "", &ext_url])
                .no_window()
                .spawn();

            #[cfg(target_os = "macos")]
            let _ = Command::new("open").arg(&ext_url).spawn();

            #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
            let _ = Command::new("xdg-open").arg(&ext_url).spawn();
        }
        let body = r#"{"ok":true}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/restart_app") {
        if let Ok(guard) = state.lock() {
            save_game_sessions(&guard.game_sessions);
        }
        stop_fps_etw_session();
        let body = r#"{"ok":true}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
        let _ = stream.flush();
        thread::spawn(|| {
            thread::sleep(Duration::from_millis(200));
            if std::env::var("COREFLOW_SUPERVISED").is_err() {
                if let Ok(exe) = std::env::current_exe() {
                    #[cfg(target_os = "windows")]
                    let _ = Command::new("cmd")
                        .args(["/C", "start", "", &exe.to_string_lossy()])
                        .no_window()
                        .spawn();

                    #[cfg(target_os = "macos")]
                    let _ = Command::new("open").arg(&exe).spawn();

                    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
                    let _ = Command::new(&exe).spawn();
                }
                std::process::exit(0);
            } else {
                std::process::exit(42);
            }
        });
        return;
    } else if first_line.starts_with("POST /api/quit") || first_line.starts_with("GET /api/quit") {
        if now_secs() < SUPPRESS_QUIT_UNTIL.load(Ordering::SeqCst) {
            // 자동 복구로 닫히는 이전 창의 종료 요청은 무시
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
            let _ = stream.write_all(resp.as_bytes());
            return;
        }
        if let Ok(guard) = state.lock() {
            save_game_sessions(&guard.game_sessions);
        }
        stop_fps_etw_session();
        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
        let _ = stream.write_all(resp.as_bytes());
        let _ = stream.flush();
        thread::sleep(Duration::from_millis(100));
        std::process::exit(0);
    } else {
        let saved_mode = load_theme_pref();
        let saved_todos = load_todos_json();
        let saved_alerts = load_alerts_json();
        let saved_ui_prefs = load_ui_prefs_json();
        let ms = load_minihud_state();
        let saved_minihud = format!(
            "{{\"is_mini\":{},\"wide\":{},\"topmost\":{},\"mini_x\":{},\"mini_y\":{},\"mini_w\":{},\"mini_h\":{},\"normal_x\":{},\"normal_y\":{},\"normal_w\":{},\"normal_h\":{}}}",
            ms.is_mini, ms.wide, ms.topmost, ms.mini_x, ms.mini_y, ms.mini_w, ms.mini_h,
            ms.normal_x, ms.normal_y, ms.normal_w, ms.normal_h
        );
        let body = INDEX_HTML
            .replace(
                "let themeOverride = 'auto';",
                &format!("let themeOverride = '{saved_mode}';"),
            )
            .replace("__COREFLOW_SESSION_TOKEN__", session_token)
            .replace("__COREFLOW_APP_VERSION__", APP_VERSION)
            .replace("/*__COREFLOW_INITIAL_TODOS__*/[]", &saved_todos)
            .replace("/*__COREFLOW_INITIAL_ALERTS__*/null", &saved_alerts)
            .replace("/*__COREFLOW_INITIAL_UI_PREFS__*/null", &saved_ui_prefs)
            .replace("/*__COREFLOW_INITIAL_MINIHUD__*/null", &saved_minihud);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    }
}

const APP_WINDOW_TITLE: &str = "CoreFlow — 시스템 모니터링 & 집중 스튜디오";

/// 창 자동 복구 중에는 이전 창이 보내는 종료 요청(/api/quit)을 무시하기 위한 기한(UNIX 초)
static SUPPRESS_QUIT_UNTIL: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "windows")]
fn find_app_window() -> isize {
    let title_w = to_wide(APP_WINDOW_TITLE);
    let exact = unsafe { FindWindowW(std::ptr::null(), title_w.as_ptr()) };
    if exact != 0 {
        return exact;
    }
    unsafe {
        let mut child: isize = 0;
        loop {
            child = FindWindowExW(0, child, std::ptr::null(), std::ptr::null());
            if child == 0 {
                break;
            }
            if IsWindowVisible(child) == 0 {
                continue;
            }
            let len = GetWindowTextLengthW(child);
            if len <= 0 {
                continue;
            }
            let mut buf = vec![0u16; (len as usize) + 1];
            let read_len = GetWindowTextW(child, buf.as_mut_ptr(), buf.len() as i32);
            if read_len > 0 {
                let text = String::from_utf16_lossy(&buf[..read_len as usize]);
                if text.starts_with("CoreFlow — 시스템 모니터링") {
                    return child;
                }
            }
        }
    }
    0
}

#[cfg(not(target_os = "windows"))]
fn find_app_window() -> isize {
    0
}

/// 이전(멈춘) CoreFlow 창이 남아 있으면 정상 종료 메시지(WM_CLOSE)를 보내 정리
#[cfg(target_os = "windows")]
fn close_stale_app_window() {
    const WM_CLOSE: u32 = 0x0010;
    for _ in 0..5 {
        let hwnd = find_app_window();
        if hwnd == 0 {
            return;
        }
        unsafe {
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
        }
        thread::sleep(Duration::from_millis(600));
    }
}

#[cfg(not(target_os = "windows"))]
fn close_stale_app_window() {}

#[cfg(target_os = "windows")]
fn is_window_minimized(hwnd: isize) -> bool {
    unsafe { IsIconic(hwnd) != 0 }
}

#[cfg(not(target_os = "windows"))]
fn is_window_minimized(_hwnd: isize) -> bool {
    false
}

#[cfg(target_os = "windows")]
fn is_window_os_hung(hwnd: isize) -> bool {
    unsafe { IsHungAppWindow(hwnd) != 0 }
}

#[cfg(not(target_os = "windows"))]
fn is_window_os_hung(_hwnd: isize) -> bool {
    false
}

#[cfg(target_os = "windows")]
fn close_window_handle(hwnd: isize) {
    const WM_CLOSE: u32 = 0x0010;
    unsafe {
        PostMessageW(hwnd, WM_CLOSE, 0, 0);
    }
}

#[cfg(not(target_os = "windows"))]
fn close_window_handle(_hwnd: isize) {}

fn append_watchdog_log(msg: &str) {
    let path = get_logs_dir().join("coreflow_watchdog.log");
    // 로그 파일이 1MB를 넘으면 새로 시작
    if std::fs::metadata(&path).map(|m| m.len() > 1024 * 1024).unwrap_or(false) {
        let _ = std::fs::remove_file(&path);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "[{}] {}", now_secs(), msg);
    }
}

/// 새 CoreFlow 실행 시 기존에 떠 있던 이전 버전/중복 CoreFlow 창과 프로세스를 정리
fn terminate_existing_coreflow_instances() {
    close_stale_app_window();
    let my_pid = std::process::id();
    let mut sys = System::new_all();
    sys.refresh_all();
    let mut killed = false;
    for (pid, proc_info) in sys.processes() {
        let p = pid.as_u32();
        if p == my_pid {
            continue;
        }
        let name_lower = proc_info.name().to_string_lossy().to_lowercase();
        if name_lower == "coreflow.exe" || name_lower == "coreflow" {
            if proc_info.kill() {
                killed = true;
            }
        }
    }
    if killed {
        thread::sleep(Duration::from_millis(350));
    }
}

/// 감시자(Supervisor) 프로세스: 실제 모니터링 워커를 자식으로 실행하고,
/// 워커가 비정상 종료(크래시/교착 상태 감지)되면 자동으로 다시 실행합니다.
/// 사용자가 정상적으로 종료(종료 코드 0)한 경우에는 함께 종료됩니다.
fn run_supervisor() {
    terminate_existing_coreflow_instances();
    let Ok(exe) = std::env::current_exe() else {
        run_worker(false);
        return;
    };
    let mut restart_times: Vec<Instant> = Vec::new();
    let mut is_restart = false;

    loop {
        let mut cmd = Command::new(&exe);
        cmd.arg("--worker");
        cmd.env("COREFLOW_SUPERVISED", "1");
        if is_restart {
            cmd.arg("--restarted");
        }
        let child = cmd.no_window().spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(_) => {
                // 자식 프로세스 실행이 불가능한 환경이면 감시 없이 직접 실행
                run_worker(is_restart);
                return;
            }
        };

        let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
        if code == 0 {
            return; // 사용자 정상 종료
        }

        if code == 42 {
            append_watchdog_log("사용자 요청에 의한 프로그램 재시작 (exit code 42)");
            restart_times.clear();
            is_restart = true;
            thread::sleep(Duration::from_millis(300));
            continue;
        }

        append_watchdog_log(&format!(
            "워커 비정상 종료 감지 (exit code {code}) → 자동 재시작"
        ));

        // 5분 내 8회 이상 연속 크래시하면 무한 재시작 루프 방지를 위해 중단
        let now = Instant::now();
        restart_times.retain(|t| now.duration_since(*t) < Duration::from_secs(300));
        restart_times.push(now);
        if restart_times.len() > 8 {
            append_watchdog_log("5분 내 재시작 횟수 초과 → 감시 중단");
            return;
        }
        is_restart = true;
        thread::sleep(Duration::from_millis(1500));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--worker") {
        let restarted = args.iter().any(|a| a == "--restarted");
        run_worker(restarted);
    } else {
        run_supervisor();
    }
}

fn run_worker(restarted: bool) {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let _ = std::env::set_current_dir(dir);
        }
    }

    // 패닉 발생 시 원인을 로그로 남김 (진단용)
    std::panic::set_hook(Box::new(|info| {
        append_watchdog_log(&format!("패닉 발생: {info}"));
    }));

    if restarted {
        close_stale_app_window();
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind local port");
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");
    let session_token = Arc::new(generate_session_token());

    let gpu_state = Arc::new(Mutex::new(GpuMetrics::default()));
    spawn_gpu_monitor(Arc::clone(&gpu_state));
    spawn_fps_etw_monitor();

    let cpu_temp_state = Arc::new(Mutex::new(None));
    spawn_cpu_thermal_monitor(Arc::clone(&cpu_temp_state));

    let ping_state = Arc::new(Mutex::new(PingMetrics::default()));
    let active_game_target = Arc::new(Mutex::new((0u32, String::new())));
    spawn_ping_monitor(Arc::clone(&ping_state), Arc::clone(&active_game_target));

    let initial_theme = query_windows_theme();
    let theme_state = Arc::new(Mutex::new(initial_theme));
    spawn_theme_watcher(Arc::clone(&theme_state));

    let disks_state = Arc::new(Mutex::new(Vec::<String>::new()));
    spawn_disk_monitor(Arc::clone(&disks_state));

    let state = Arc::new(Mutex::new(SharedState::new(
        Arc::clone(&gpu_state),
        Arc::clone(&cpu_temp_state),
        Arc::clone(&theme_state),
        Arc::clone(&ping_state),
        Arc::clone(&disks_state),
        Arc::clone(&active_game_target),
    )));
    let last_heartbeat = Arc::new(AtomicU64::new(now_secs()));
    let client_connected = Arc::new(AtomicBool::new(false));

    // [감시 1] 창 상태 감시: 창이 닫히면 정상 종료, 창이 응답 없음(멈춤)이면 창을 닫고 다시 띄움
    {
        let last_hb = Arc::clone(&last_heartbeat);
        let connected = Arc::clone(&client_connected);
        let st = Arc::clone(&state);
        let url_c = url.clone();
        thread::spawn(move || {
            let started = Instant::now();
            let mut seen_window = false;
            let mut missing_since: Option<Instant> = None;
            let mut hung_since: Option<Instant> = None;
            let mut last_relaunch = Instant::now();

            loop {
                thread::sleep(Duration::from_secs(2));
                let hwnd = find_app_window();

                if hwnd != 0 {
                    seen_window = true;
                    missing_since = None;

                    let minimized = is_window_minimized(hwnd);
                    let os_hung = is_window_os_hung(hwnd);
                    let stale_secs = now_secs().saturating_sub(last_hb.load(Ordering::SeqCst));
                    let ui_stalled = connected.load(Ordering::SeqCst) && stale_secs > 45 && !minimized;

                    if os_hung || ui_stalled {
                        let since = *hung_since.get_or_insert_with(Instant::now);
                        if since.elapsed() >= Duration::from_secs(10)
                            && last_relaunch.elapsed() >= Duration::from_secs(60)
                        {
                            append_watchdog_log(&format!(
                                "UI 멈춤 감지 (응답없음={os_hung}, 하트비트 {stale_secs}초 지연) → 창 자동 복구"
                            ));
                            SUPPRESS_QUIT_UNTIL.store(now_secs() + 15, Ordering::SeqCst);
                            close_window_handle(hwnd);
                            thread::sleep(Duration::from_millis(1500));
                            launch_desktop_window(&url_c);
                            spawn_window_icon_applier();
                            last_hb.store(now_secs(), Ordering::SeqCst);
                            last_relaunch = Instant::now();
                            hung_since = None;
                        }
                    } else {
                        hung_since = None;
                    }
                } else {
                    // 창이 보이지 않음: 사용자가 닫았거나 아직 뜨지 않음
                    let since = *missing_since.get_or_insert_with(Instant::now);
                    let limit = if seen_window {
                        Duration::from_secs(8)
                    } else {
                        Duration::from_secs(90)
                    };
                    let hb_stale = now_secs().saturating_sub(last_hb.load(Ordering::SeqCst)) > 8;
                    if since.elapsed() > limit && hb_stale && started.elapsed() > Duration::from_secs(10) {
                        if let Ok(guard) = st.try_lock() {
                            save_game_sessions(&guard.game_sessions);
                        }
                        stop_fps_etw_session();
                        std::process::exit(0);
                    }
                }
            }
        });
    }

    // [감시 2] 백엔드 교착(Deadlock) 감시: 상태 잠금이 45초 이상 풀리지 않으면 워커를 재시작
    {
        let st = Arc::clone(&state);
        thread::spawn(move || {
            let mut stuck_since: Option<Instant> = None;
            loop {
                thread::sleep(Duration::from_secs(3));
                match st.try_lock() {
                    Ok(_) | Err(std::sync::TryLockError::Poisoned(_)) => stuck_since = None,
                    Err(std::sync::TryLockError::WouldBlock) => {
                        let since = *stuck_since.get_or_insert_with(Instant::now);
                        if since.elapsed() > Duration::from_secs(45) {
                            append_watchdog_log("백엔드 교착 상태 감지 (45초 초과) → 워커 자동 재시작");
                            std::process::exit(3);
                        }
                    }
                }
            }
        });
    }

    launch_desktop_window(&url);
    spawn_window_icon_applier();

    for stream in listener.incoming().flatten() {
        let state_clone = Arc::clone(&state);
        let hb_clone = Arc::clone(&last_heartbeat);
        let conn_clone = Arc::clone(&client_connected);
        let tok_clone = Arc::clone(&session_token);
        thread::spawn(move || {
            // 요청 처리 중 패닉이 나도 서버 전체가 멈추지 않도록 격리
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handle_client(stream, &state_clone, &hb_clone, &conn_clone, &tok_clone);
            }));
        });
    }
}

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CoreFlow — 시스템 모니터링 & 집중 스튜디오</title>
<link rel="icon" type="image/x-icon" href="/favicon.ico?v=3">
<link rel="shortcut icon" type="image/x-icon" href="/favicon.ico?v=3">
<style>
  :root {
    --brand: #0078d4;
    --brand-rgb: 0, 120, 212;
    --green: #23a55a;
    --neon-green: #00c875;
    --yellow: #d99b00;
    --red: #e53935;
    --cyan: #0099cc;
    --purple: #8e44ad;
    --orange: #e66700;

    /* 기본 다크 테마 변수 */
    --bg-tertiary: #1e1f22;
    --bg-secondary: #2b2d31;
    --bg-primary: #313338;
    --bg-card: #232428;
    --bg-hover: #35373c;
    --bg-active: #404249;
    --text-normal: #f2f3f5;
    --text-muted: #949ba4;
    --border-subtle: rgba(255, 255, 255, 0.07);
    --header-border: rgba(0, 0, 0, 0.28);
    --card-shadow: 0 4px 14px rgba(0, 0, 0, 0.18);
    --grid-line: rgba(255, 255, 255, 0.06);
  }

  /* Windows 라이트 테마 동기화 클래스 */
  body.theme-light {
    --bg-tertiary: #e3e5e8;
    --bg-secondary: #f2f3f5;
    --bg-primary: #ffffff;
    --bg-card: #ebedef;
    --bg-hover: #dfe1e5;
    --bg-active: #d4d7dc;
    --text-normal: #060607;
    --text-muted: #4e5058;
    --border-subtle: rgba(0, 0, 0, 0.08);
    --header-border: rgba(0, 0, 0, 0.08);
    --card-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
    --grid-line: rgba(0, 0, 0, 0.06);
    --neon-green: #158f48;
    --cyan: #0078d4;
  }

  * {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
    user-select: none;
  }

  body {
    font-family: 'Pretendard', 'Malgun Gothic', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background-color: var(--bg-primary);
    color: var(--text-normal);
    height: 100vh;
    width: 100vw;
    overflow: hidden;
    display: flex;
    transition: background-color 0.25s ease, color 0.25s ease;
  }

  /* 1. 디스코드 좌측 서버 아이콘 레일 */
  .server-rail {
    width: 72px;
    background-color: var(--bg-tertiary);
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 12px 0;
    gap: 8px;
    flex-shrink: 0;
    transition: background-color 0.25s ease;
  }

  .server-icon {
    width: 48px;
    height: 48px;
    border-radius: 50%;
    background-color: var(--bg-primary);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 22px;
    cursor: pointer;
    transition: all 0.2s cubic-bezier(0.2, 0.8, 0.2, 1);
    position: relative;
    color: var(--text-normal);
    box-shadow: 0 2px 6px rgba(0,0,0,0.08);
  }

  .server-icon::before {
    content: '';
    position: absolute;
    left: -12px;
    width: 4px;
    height: 0;
    border-radius: 0 4px 4px 0;
    background-color: var(--brand);
    transition: height 0.2s ease;
  }

  .server-icon:hover {
    border-radius: 16px;
    background-color: var(--brand);
    color: #fff;
  }

  .server-icon:hover::before {
    height: 20px;
  }

  .server-icon.active {
    border-radius: 16px;
    background-color: var(--brand);
    color: #fff;
  }

  .server-icon.active::before {
    height: 40px;
  }

  .rail-divider {
    width: 32px;
    height: 2px;
    background-color: var(--border-subtle);
    margin: 4px 0;
  }

  /* 2. 채널 사이드바 */
  .channel-sidebar {
    width: 245px;
    background-color: var(--bg-secondary);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
    transition: background-color 0.25s ease;
  }

  .server-header {
    height: 48px;
    padding: 0 16px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-weight: 700;
    font-size: 15px;
    border-bottom: 1px solid var(--header-border);
    letter-spacing: 0.3px;
  }

  .channel-list {
    flex: 1;
    padding: 12px 8px;
    overflow-y: auto;
  }

  .category-label {
    font-size: 11px;
    font-weight: 700;
    color: var(--text-muted);
    padding: 8px 8px 4px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
  }

  .channel-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px;
    border-radius: 6px;
    color: var(--text-muted);
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    margin-bottom: 2px;
    transition: background 0.12s, color 0.12s;
  }

  .channel-item:hover {
    background-color: var(--bg-hover);
    color: var(--text-normal);
  }

  .channel-item.active {
    background-color: rgba(var(--brand-rgb), 0.16);
    color: var(--brand);
    font-weight: 700;
  }

  .channel-hash {
    font-size: 18px;
    color: inherit;
    opacity: 0.75;
    font-weight: 400;
  }

  .voice-status-box {
    margin: 8px;
    padding: 10px 12px;
    border-radius: 8px;
    background-color: rgba(35, 165, 90, 0.1);
    border: 1px solid rgba(35, 165, 90, 0.25);
  }

  .voice-status-title {
    font-size: 12px;
    font-weight: 700;
    color: var(--green);
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .pulse-dot {
    width: 8px;
    height: 8px;
    background-color: var(--green);
    border-radius: 50%;
    box-shadow: 0 0 8px var(--green);
    animation: pulse 1.5s infinite;
  }

  @keyframes pulse {
    0% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.5; transform: scale(1.2); }
    100% { opacity: 1; transform: scale(1); }
  }

  .voice-status-sub {
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 4px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  /* 디스코드 스타일 활동 중(Playing a Game) 배너 */
  .playing-box {
    margin: 8px;
    padding: 10px 12px;
    border-radius: 8px;
    background-color: rgba(var(--brand-rgb), 0.1);
    border: 1px solid rgba(var(--brand-rgb), 0.3);
  }

  .playing-header {
    font-size: 10px;
    font-weight: 800;
    text-transform: uppercase;
    color: var(--brand);
    letter-spacing: 0.6px;
  }

  .playing-title {
    font-size: 13px;
    font-weight: 700;
    color: var(--text-normal);
    margin-top: 3px;
  }

  .playing-fps {
    font-size: 12px;
    color: var(--neon-green);
    font-weight: 700;
    margin-top: 2px;
  }

  /* 하단 유저 프로필 패널 */
  .user-panel {
    height: 54px;
    background-color: var(--bg-card);
    padding: 0 10px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-top: 1px solid var(--border-subtle);
  }

  .user-info {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .avatar {
    width: 34px;
    height: 34px;
    border-radius: 50%;
    background: var(--brand);
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 800;
    font-size: 15px;
    position: relative;
    cursor: pointer;
    flex-shrink: 0;
  }

  .avatar-img {
    width: 100%;
    height: 100%;
    border-radius: 50%;
    object-fit: cover;
    display: block;
  }

  .startup-box {
    margin: 8px;
    padding: 9px 12px;
    border-radius: 8px;
    background-color: var(--bg-card);
    border: 1px solid var(--border-subtle);
    display: flex;
    align-items: center;
    justify-content: space-between;
    cursor: pointer;
    transition: border-color 0.15s, background-color 0.15s;
  }

  .startup-box:hover {
    border-color: var(--brand);
    background-color: var(--bg-hover);
  }

  .startup-label {
    font-size: 12px;
    font-weight: 700;
    color: var(--text-normal);
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .switch-pill {
    font-size: 10.5px;
    font-weight: 800;
    padding: 2px 8px;
    border-radius: 999px;
    background-color: var(--bg-active);
    color: var(--text-muted);
    transition: all 0.15s;
  }

  .switch-pill.on {
    background-color: var(--green);
    color: #fff;
  }

  .avatar-status {
    position: absolute;
    bottom: -1px;
    right: -1px;
    width: 11px;
    height: 11px;
    background-color: var(--green);
    border: 2px solid var(--bg-card);
    border-radius: 50%;
  }

  .user-name {
    font-size: 13px;
    font-weight: 700;
    line-height: 1.2;
  }

  .user-tag {
    font-size: 11px;
    color: var(--text-muted);
  }

  .icon-btn {
    background: transparent;
    border: none;
    color: var(--text-muted);
    width: 32px;
    height: 32px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 15px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .icon-btn:hover {
    background-color: var(--bg-hover);
    color: var(--text-normal);
  }

  .icon-btn.danger:hover {
    background-color: rgba(229, 57, 53, 0.2);
    color: var(--red);
  }

  /* 3. 메인 컨텐츠 영역 */
  .main-view {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    background-color: var(--bg-primary);
    overflow: hidden;
    transition: background-color 0.25s ease;
  }

  .top-bar {
    height: 48px;
    padding: 0 18px;
    border-bottom: 1px solid var(--header-border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-shrink: 0;
  }

  .top-bar-left {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
    flex: 1;
    overflow: hidden;
  }

  .top-bar-title {
    font-weight: 700;
    font-size: 15.5px;
    white-space: nowrap;
    flex-shrink: 0;
  }

  .top-bar-desc {
    font-size: 12px;
    color: var(--text-muted);
    padding-left: 10px;
    border-left: 1px solid var(--border-subtle);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
  }

  .top-bar-right {
    display: flex;
    align-items: center;
    gap: 7px;
    flex-shrink: 0;
  }

  .badge {
    font-size: 10.5px;
    padding: 3px 8px;
    border-radius: 999px;
    background-color: var(--bg-card);
    color: var(--text-muted);
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 5px;
    border: 1px solid var(--border-subtle);
    white-space: nowrap;
    flex-shrink: 0;
  }

  .accent-dot {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background-color: var(--brand);
    display: inline-block;
  }

  .content-scroll {
    flex: 1;
    min-width: 0;
    min-height: 0;
    padding: 16px 18px;
    overflow-y: auto;
    overflow-x: hidden;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  /* 대시보드 그리드 & 카드 */
  .grid-4 {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 12px;
    flex-shrink: 0;
    width: 100%;
    min-width: 0;
  }

  .grid-main {
    display: grid;
    grid-template-columns: minmax(0, 1.35fr) minmax(0, 1fr);
    grid-template-rows: minmax(0, 1fr);
    gap: 12px;
    flex: 1 1 0;
    min-height: 320px;
    width: 100%;
    min-width: 0;
  }

  .card {
    background-color: var(--bg-secondary);
    border: 1px solid var(--border-subtle);
    border-radius: 12px;
    padding: 13px 14px;
    display: flex;
    flex-direction: column;
    gap: 9px;
    min-width: 0;
    overflow: hidden;
    box-shadow: var(--card-shadow);
    transition: background-color 0.25s ease, border-color 0.25s ease;
  }

  .card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    min-width: 0;
  }

  .card-title {
    font-size: clamp(11px, 0.95vw, 12.5px);
    font-weight: 700;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.2px;
    display: flex;
    align-items: center;
    gap: 4px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
  }

  .zoom-card {
    cursor: pointer;
    position: relative;
    transition: transform 0.15s ease, border-color 0.2s ease, box-shadow 0.2s ease;
  }

  .zoom-card:hover {
    border-color: var(--brand);
    transform: translateY(-2px);
  }

  /* 더블클릭 전체 화면 상세 모니터링 뷰 */
  .detail-overlay {
    position: fixed;
    inset: 0;
    z-index: 8500;
    background-color: var(--bg-primary);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    animation: fadeIn 0.18s ease;
  }

  @keyframes fadeIn {
    from { opacity: 0; transform: scale(0.985); }
    to { opacity: 1; transform: scale(1); }
  }

  .detail-header {
    height: 58px;
    background-color: var(--bg-secondary);
    border-bottom: 1px solid var(--header-border);
    padding: 0 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-shrink: 0;
  }

  .detail-title-wrap {
    display: flex;
    align-items: center;
    gap: 12px;
    min-width: 0;
    flex: 1;
    overflow: hidden;
  }

  .detail-title {
    font-size: 17px;
    font-weight: 800;
    white-space: nowrap;
    flex-shrink: 0;
  }

  .detail-sub {
    font-size: 12.5px;
    color: var(--text-muted);
    padding-left: 12px;
    border-left: 1px solid var(--border-subtle);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
  }

  .detail-body {
    flex: 1;
    padding: 20px 24px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 16px;
    min-height: 0;
  }

  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 12px;
    flex-shrink: 0;
  }

  .kpi-box {
    background-color: var(--bg-secondary);
    border: 1px solid var(--border-subtle);
    border-radius: 10px;
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .kpi-label {
    font-size: 11px;
    font-weight: 700;
    color: var(--text-muted);
    text-transform: uppercase;
  }

  .kpi-val {
    font-size: 24px;
    font-weight: 800;
    font-variant-numeric: tabular-nums;
  }

  .detail-chart-wrap {
    background-color: var(--bg-secondary);
    border: 1px solid var(--border-subtle);
    border-radius: 12px;
    padding: 18px 20px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .detail-canvas {
    width: 100%;
    height: 270px;
    background-color: var(--bg-card);
    border-radius: 10px;
    border: 1px solid var(--border-subtle);
    display: block;
  }

  /* 녹화 버튼 및 분석 리포트 스타일 */
  .rec-btn {
    display: flex;
    align-items: center;
    gap: 7px;
    padding: 6px 12px;
    border-radius: 8px;
    font-size: 12px;
    font-weight: 700;
    cursor: pointer;
    border: 1px solid rgba(229, 57, 53, 0.45);
    background-color: rgba(229, 57, 53, 0.12);
    color: var(--text-normal);
    transition: all 0.15s ease;
    white-space: nowrap;
  }

  .rec-btn:hover {
    background-color: rgba(229, 57, 53, 0.24);
  }

  .rec-btn.recording {
    background-color: var(--red);
    color: #fff;
    border-color: var(--red);
    box-shadow: 0 0 12px rgba(229, 57, 53, 0.45);
  }

  .rec-dot {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background-color: var(--red);
    display: inline-block;
  }

  .rec-btn.recording .rec-dot {
    background-color: #fff;
    animation: pulse 0.9s infinite;
  }

  .insight-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
  }

  .insight-card {
    background-color: var(--bg-secondary);
    border: 1px solid var(--border-subtle);
    border-left: 4px solid var(--brand);
    border-radius: 10px;
    padding: 13px 15px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .insight-title {
    font-size: 12px;
    font-weight: 800;
    color: var(--text-header);
  }

  .insight-body {
    font-size: 12px;
    line-height: 1.45;
    color: var(--text-normal);
  }

  .series-toggles {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
  }

  .series-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 11.5px;
    font-weight: 700;
    cursor: pointer;
    border: 1px solid var(--border-subtle);
    background-color: var(--bg-card);
    color: var(--text-muted);
    transition: all 0.12s;
  }

  .series-pill.active {
    color: var(--text-normal);
    border-color: var(--brand);
    background-color: rgba(var(--brand-rgb), 0.14);
  }

  .scrub-inspector {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 14px;
    border-radius: 8px;
    background-color: var(--bg-card);
    border: 1px solid var(--border-subtle);
    font-size: 12px;
    font-variant-numeric: tabular-nums;
  }

  .metric-big {
    font-size: clamp(18px, 1.7vw, 25px);
    font-weight: 800;
    letter-spacing: -0.5px;
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
  }

  .metric-sub {
    font-size: 11.5px;
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
  }

  .stat-pills {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }

  .stat-pill {
    font-size: 11px;
    background-color: var(--bg-card);
    padding: 3px 8px;
    border-radius: 6px;
    color: var(--text-normal);
    font-variant-numeric: tabular-nums;
    border: 1px solid var(--border-subtle);
    white-space: nowrap;
  }

  /* 프로그레스 바 */
  .progress-track {
    width: 100%;
    height: 8px;
    background-color: var(--bg-tertiary);
    border-radius: 999px;
    overflow: hidden;
  }

  .progress-fill {
    height: 100%;
    border-radius: 999px;
    transition: width 0.35s ease;
  }

  .chart-canvas {
    width: 100%;
    height: 80px;
    background-color: var(--bg-card);
    border-radius: 8px;
    display: block;
    border: 1px solid var(--border-subtle);
  }

  /* 수치 그리드(Metric Grid) 화면 모드 전용 스타일 */
  .metric-num-grid {
    display: none;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 6px;
    margin-top: 4px;
    padding-top: 6px;
    border-top: 1px dashed var(--border-subtle);
  }

  .view-mode-grid .chart-canvas {
    display: none !important;
  }

  .view-mode-grid .metric-num-grid {
    display: grid !important;
  }

  .view-mode-grid .stat-pills {
    display: none !important;
  }

  .view-mode-grid .strip-chart-view {
    display: none !important;
  }

  .view-mode-grid .strip-grid-view {
    display: grid !important;
  }

  .num-cell {
    background-color: var(--bg-card);
    border: 1px solid var(--border-subtle);
    border-radius: 6px;
    padding: 5px 8px;
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .num-cell.full-span {
    grid-column: span 2;
  }

  .num-lbl {
    font-size: 10px;
    font-weight: 700;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.3px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .num-val {
    font-size: 12.5px;
    font-weight: 800;
    font-variant-numeric: tabular-nums;
    color: var(--text-normal);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .num-sub {
    font-size: 10px;
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .core-mini-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(46px, 1fr));
    gap: 3px;
    max-height: 58px;
    overflow-y: auto;
    padding-right: 2px;
  }

  .core-mini-chip {
    background-color: var(--bg-secondary);
    border: 1px solid var(--border-subtle);
    border-radius: 4px;
    padding: 2px 4px;
    font-size: 9.5px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-variant-numeric: tabular-nums;
  }

  .core-mini-chip.high {
    border-color: rgba(229, 57, 53, 0.5);
    background-color: rgba(229, 57, 53, 0.15);
    color: var(--red);
  }

  /* 상세보기(Detail Overlay) 수치 그리드 전용 스타일 */
  .detail-grid-panel {
    display: none;
    flex-direction: column;
    gap: 14px;
    flex: 1 1 auto;
    min-height: 0;
  }

  .view-mode-grid .detail-chart-wrap {
    display: none !important;
  }

  .view-mode-grid .detail-grid-panel {
    display: flex !important;
  }

  .detail-grid-row {
    display: grid;
    grid-template-columns: minmax(0, 1.05fr) minmax(0, 1.25fr);
    gap: 14px;
    flex: 1 1 0;
    min-height: 0;
    width: 100%;
  }

  .detail-grid-row.equal-cols {
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  }

  .detail-card-auto {
    height: 100%;
    min-height: 0;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .detail-num-table-wrap {
    flex: 1 1 auto;
    min-height: 0;
    overflow-y: auto;
    border-radius: 6px;
    border: 1px solid var(--border-subtle);
    background-color: var(--bg-card);
  }

  .detail-num-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }

  .detail-num-table th {
    position: sticky;
    top: 0;
    background-color: var(--bg-tertiary);
    color: var(--text-muted);
    padding: 8px 12px;
    font-size: 11.5px;
    font-weight: 700;
    text-transform: uppercase;
    text-align: left;
    border-bottom: 1px solid var(--border-subtle);
    z-index: 2;
  }

  .detail-num-table td {
    padding: 7px 12px;
    border-bottom: 1px solid var(--border-subtle);
    font-variant-numeric: tabular-nums;
  }

  .detail-num-table tr:last-child td {
    border-bottom: none;
  }

  .detail-subgrid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
    gap: 8px;
  }

  .detail-subgrid-card {
    background-color: var(--bg-card);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    padding: 8px 10px;
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }

  /* 프로세스 테이블 & 드롭다운 */
  .proc-name-cell {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    min-width: 0;
    max-width: 100%;
  }

  .proc-icon {
    width: 16px;
    height: 16px;
    object-fit: contain;
    flex-shrink: 0;
    border-radius: 3px;
    vertical-align: middle;
  }

  .search-input, .select-input {
    background-color: var(--bg-primary);
    border: 1px solid var(--border-subtle);
    color: var(--text-normal);
    padding: 5px 10px;
    border-radius: 6px;
    font-size: 12px;
    outline: none;
    white-space: nowrap;
    flex-shrink: 0;
  }

  .search-input:focus, .select-input:focus {
    border-color: var(--brand);
  }

  .table-wrap {
    flex: 1 1 auto;
    min-height: 120px;
    overflow-y: auto;
    border-radius: 8px;
    background-color: var(--bg-card);
    border: 1px solid var(--border-subtle);
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }

  th {
    position: sticky;
    top: 0;
    background-color: var(--bg-tertiary);
    color: var(--text-muted);
    text-align: left;
    padding: 8px 12px;
    font-size: 11px;
    text-transform: uppercase;
    cursor: pointer;
    transition: color 0.15s, background-color 0.15s;
    white-space: nowrap;
  }

  th:hover {
    color: var(--text-normal);
    background-color: var(--bg-hover);
  }

  th.active-sort {
    color: var(--brand);
    font-weight: 800;
  }

  td {
    padding: 7px 12px;
    border-bottom: 1px solid var(--border-subtle);
  }

  tbody tr {
    cursor: context-menu;
  }

  tbody tr:hover td {
    background-color: var(--bg-hover);
  }

  /* 커스텀 우클릭 컨텍스트 메뉴 */
  .ctx-menu {
    position: fixed;
    z-index: 9999;
    min-width: 210px;
    background-color: var(--bg-tertiary);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    padding: 6px;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .ctx-header {
    padding: 6px 10px;
    font-size: 11px;
    font-weight: 700;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border-subtle);
    margin-bottom: 4px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 240px;
  }

  .ctx-item {
    padding: 8px 10px;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-normal);
    border-radius: 5px;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 8px;
    background: transparent;
    border: none;
    text-align: left;
    width: 100%;
  }

  .ctx-item:hover {
    background-color: var(--brand);
    color: #fff;
  }

  .ctx-item.danger {
    color: var(--red);
  }

  .ctx-item.danger:hover {
    background-color: var(--red);
    color: #fff;
  }

  /* 하단 토스트 알림 */
  .toast {
    position: fixed;
    bottom: 22px;
    right: 24px;
    z-index: 10000;
    background-color: var(--bg-tertiary);
    color: var(--text-normal);
    border: 1px solid var(--brand);
    padding: 10px 16px;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 600;
    box-shadow: 0 6px 20px rgba(0, 0, 0, 0.3);
    transition: opacity 0.25s ease, transform 0.25s ease;
  }

  /* 뽀모도로 타이머 */
  .pomo-box {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background-color: var(--bg-card);
    padding: 14px 16px;
    border-radius: 10px;
    gap: 12px;
    border: 1px solid var(--border-subtle);
  }

  .pomo-time {
    font-size: 34px;
    font-weight: 800;
    font-variant-numeric: tabular-nums;
    letter-spacing: 1px;
  }

  .btn-group {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }

  .btn {
    background-color: var(--brand);
    color: #fff;
    border: none;
    padding: 6px 11px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: filter 0.15s, transform 0.08s;
    white-space: nowrap;
    flex-shrink: 0;
  }

  .btn:hover {
    filter: brightness(1.1);
  }

  .btn:active {
    transform: scale(0.97);
  }

  .btn.secondary {
    background-color: var(--bg-active);
    color: var(--text-normal);
  }

  .btn.success {
    background-color: var(--green);
    color: #fff;
  }

  /* 할 일 (Todo) 리스트 */
  .todo-input-row {
    display: flex;
    gap: 8px;
  }

  .todo-input {
    flex: 1;
    background-color: var(--bg-primary);
    border: 1px solid var(--border-subtle);
    color: var(--text-normal);
    padding: 9px 12px;
    border-radius: 8px;
    font-size: 13px;
    outline: none;
  }

  .todo-input:focus {
    border-color: var(--brand);
  }

  .todo-list {
    display: flex;
    flex-direction: column;
    gap: 6px;
    flex: 1 1 0;
    min-height: 0;
    overflow-y: auto;
  }

  .todo-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background-color: var(--bg-card);
    padding: 9px 12px;
    border-radius: 8px;
    cursor: pointer;
    transition: background 0.12s;
    border: 1px solid var(--border-subtle);
  }

  .todo-item:hover {
    background-color: var(--bg-hover);
  }

  .todo-left {
    display: flex;
    align-items: center;
    gap: 10px;
    flex: 1;
  }

  .checkbox {
    width: 18px;
    height: 18px;
    border-radius: 5px;
    border: 2px solid var(--text-muted);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 12px;
    flex-shrink: 0;
  }

  .todo-item.done .checkbox {
    background-color: var(--brand);
    border-color: var(--brand);
    color: #fff;
  }

  .todo-item.done .todo-text {
    text-decoration: line-through;
    color: var(--text-muted);
  }

  .todo-del {
    background: transparent;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 12px;
  }

  .todo-del:hover {
    background-color: rgba(229, 57, 53, 0.15);
    color: var(--red);
  }

  /* 코어 그리드 */
  .cores-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(110px, 1fr));
    gap: 8px;
  }

  .core-chip {
    background-color: var(--bg-card);
    padding: 8px 10px;
    border-radius: 6px;
    font-size: 12px;
    border: 1px solid var(--border-subtle);
  }

  .core-chip-top {
    display: flex;
    justify-content: space-between;
    margin-bottom: 5px;
    color: var(--text-muted);
  }

  /* 게임 플레이 기록 & 랭킹 보드 스타일 */
  .gamelog-view {
    display: flex;
    flex-direction: column;
    gap: 14px;
    flex: 1 1 0;
    min-height: 0;
  }

  .rank-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
    flex: 1 1 0;
    min-height: 0;
    overflow-y: auto;
    padding-right: 2px;
  }

  .rank-item {
    background-color: var(--bg-card);
    border: 1px solid var(--border-subtle);
    border-radius: 10px;
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    transition: border-color 0.2s ease, transform 0.15s ease;
  }

  .rank-item:hover {
    border-color: var(--brand);
  }

  .rank-item.top-1 {
    border-left: 4px solid #f59f00;
  }

  .rank-item.top-2 {
    border-left: 4px solid #949ba4;
  }

  .rank-item.top-3 {
    border-left: 4px solid #d97706;
  }

  .rank-top-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
  }

  .rank-name-wrap {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }

  .rank-badge {
    font-size: 11px;
    font-weight: 800;
    padding: 2px 7px;
    border-radius: 6px;
    background-color: var(--bg-active);
    color: var(--text-normal);
    flex-shrink: 0;
  }

  .rank-badge.gold {
    background-color: rgba(245, 159, 0, 0.2);
    color: #f59f00;
  }

  .rank-title {
    font-size: 14px;
    font-weight: 800;
    color: var(--text-normal);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .rank-time-hms {
    font-size: 15px;
    font-weight: 800;
    color: var(--neon-green);
    font-variant-numeric: tabular-nums;
    flex-shrink: 0;
  }

  .rank-meta-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 11.5px;
    color: var(--text-muted);
    gap: 8px;
  }

  .filter-pills {
    display: flex;
    gap: 5px;
    align-items: center;
  }

  .filter-pill {
    background-color: var(--bg-card);
    border: 1px solid var(--border-subtle);
    color: var(--text-muted);
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 11.5px;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.15s ease;
  }

  .filter-pill:hover {
    color: var(--text-normal);
    background-color: var(--bg-hover);
  }

  .filter-pill.active {
    background-color: var(--brand);
    border-color: var(--brand);
    color: #ffffff;
  }

  .empty-state-box {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    padding: 28px 18px;
    color: var(--text-muted);
    font-size: 13px;
    line-height: 1.6;
    gap: 8px;
  }

  /* 스마트 경고 배너 및 알림 설정 스타일 */
  .live-alert-banner {
    background: linear-gradient(90deg, rgba(229, 57, 53, 0.18), rgba(230, 103, 0, 0.14));
    border: 1px solid rgba(229, 57, 53, 0.55);
    border-left: 4px solid var(--red);
    border-radius: 10px;
    padding: 10px 14px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-shrink: 0;
    animation: fadeIn 0.2s ease;
  }

  .live-alert-left {
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 0;
    flex: 1;
  }

  .live-alert-text {
    font-size: 12.5px;
    font-weight: 700;
    color: var(--text-normal);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .alert-btn-active {
    background-color: rgba(229, 57, 53, 0.2) !important;
    border-color: var(--red) !important;
    color: var(--red) !important;
    animation: pulse 1.2s infinite;
  }

  .alert-rules-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px;
  }

  .alert-rule-card {
    background-color: var(--bg-secondary);
    border: 1px solid var(--border-subtle);
    border-radius: 12px;
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    gap: 10px;
    min-width: 0;
  }

  .alert-rule-card.disabled-rule {
    opacity: 0.55;
  }

  .range-slider {
    width: 100%;
    accent-color: var(--brand);
    cursor: pointer;
  }

  /* 원클릭 컴팩트 미니 HUD 모드 스타일 */
  .mini-hud-overlay {
    position: fixed;
    inset: 0;
    z-index: 9200;
    background-color: var(--bg-primary);
    display: flex;
    flex-direction: column;
    padding: 8px 10px;
    gap: 7px;
    overflow: hidden;
  }

  .mini-hud-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    background-color: var(--bg-secondary);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    padding: 5px 9px;
    flex-shrink: 0;
  }

  .mini-hud-grid {
    flex: 1;
    min-height: 0;
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    grid-template-rows: repeat(2, minmax(0, 1fr));
    gap: 6px;
  }

  .mini-hud-overlay.layout-wide .mini-hud-grid {
    grid-template-columns: repeat(6, minmax(0, 1fr));
    grid-template-rows: minmax(0, 1fr);
  }

  .mini-hud-tile {
    background-color: var(--bg-secondary);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    padding: 6px 8px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    min-width: 0;
    overflow: hidden;
  }

  .mini-hud-label {
    font-size: 10px;
    font-weight: 800;
    color: var(--text-muted);
    text-transform: uppercase;
    display: flex;
    align-items: center;
    justify-content: space-between;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .mini-hud-val {
    font-size: clamp(14px, 3.6vw, 18px);
    font-weight: 900;
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    line-height: 1.15;
  }

  .mini-hud-sub {
    font-size: 10px;
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .mini-btn {
    background-color: var(--bg-card);
    border: 1px solid var(--border-subtle);
    color: var(--text-normal);
    font-size: 10.5px;
    font-weight: 700;
    padding: 3px 7px;
    border-radius: 5px;
    cursor: pointer;
    white-space: nowrap;
    transition: all 0.12s ease;
  }

  .mini-btn:hover {
    background-color: var(--bg-hover);
    border-color: var(--brand);
  }

  .mini-btn.active {
    background-color: var(--brand);
    border-color: var(--brand);
    color: #fff;
  }

  /* 화면·미니 HUD 맞춤 설정 스타일 */
  .custom-toggle-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
  }

  .custom-toggle-card {
    background-color: var(--bg-primary);
    border: 1.5px solid var(--border-subtle);
    border-radius: 10px;
    padding: 11px 13px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    cursor: pointer;
    user-select: none;
    transition: all 0.15s ease;
  }

  .custom-toggle-card:hover {
    border-color: var(--brand);
    background-color: var(--bg-hover);
  }

  .custom-toggle-card.active {
    border-color: var(--brand);
    background-color: rgba(var(--brand-rgb), 0.11);
  }

  .custom-toggle-card.disabled-item {
    opacity: 0.55;
  }

  .hud-style-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
  }

  .hud-style-card {
    background-color: var(--bg-primary);
    border: 2px solid var(--border-subtle);
    border-radius: 12px;
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    gap: 10px;
    cursor: pointer;
    user-select: none;
    transition: all 0.16s ease;
  }

  .hud-style-card:hover {
    border-color: var(--brand);
  }

  .hud-style-card.selected {
    border-color: var(--brand);
    background-color: rgba(var(--brand-rgb), 0.12);
    box-shadow: 0 0 0 1px var(--brand);
  }

  .hud-diagram-box {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 5px;
    padding: 8px;
    background: var(--bg-secondary);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
  }

  .hud-diagram-bar {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 4px;
    padding: 10px 8px;
    background: var(--bg-secondary);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
  }

  .hud-diagram-cell {
    height: 18px;
    border-radius: 4px;
    background: rgba(var(--brand-rgb), 0.35);
    border: 1px solid rgba(var(--brand-rgb), 0.65);
  }

  .hidden {
    display: none !important;
  }

  /* 창 크기에 따른 반응형 레이아웃 자동 조절 */
  @media (max-width: 1180px) {
    .channel-sidebar {
      width: 200px;
    }
    .content-scroll {
      padding: 12px 14px;
      gap: 12px;
    }
    .grid-4, .grid-main {
      gap: 10px;
    }
    .card {
      padding: 11px 12px;
    }
  }

  @media (max-width: 920px) {
    .grid-4 {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .grid-main {
      grid-template-columns: minmax(0, 1fr) !important;
      grid-template-rows: auto;
    }
  }
</style>
</head>
<body>
  <div id="win-accent-probe" style="color: AccentColor; display: none;"></div>

  <!-- 1. 좌측 디스코드 서버 레일 (각 메뉴 성격에 맞춘 전용 벡터 아이콘) -->
  <aside class="server-rail">
    <div class="server-icon active" onclick="switchTab('overview')" id="rail-overview" title="CoreFlow — 통합 시스템 & 게이밍 대시보드">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="3" width="7" height="7" rx="1.5"></rect>
        <rect x="14" y="3" width="7" height="7" rx="1.5"></rect>
        <rect x="14" y="14" width="7" height="7" rx="1.5"></rect>
        <rect x="3" y="14" width="7" height="7" rx="1.5"></rect>
      </svg>
    </div>
    <div class="rail-divider"></div>
    <div class="server-icon" onclick="switchTab('system')" id="rail-system" title="하드웨어 & GPU 상세 모니터">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="4" y="4" width="16" height="16" rx="2"></rect>
        <rect x="9" y="9" width="6" height="6"></rect>
        <path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"></path>
      </svg>
    </div>
    <div class="server-icon" onclick="switchTab('netdisk')" id="rail-netdisk" title="실시간 네트워크(다운로드/업로드/핑) & 디스크(용량/I/O) 모니터">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <ellipse cx="12" cy="5" rx="9" ry="3"></ellipse>
        <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path>
        <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path>
      </svg>
    </div>
    <div class="server-icon" onclick="switchTab('gamelog')" id="rail-gamelog" title="게임 플레이 기록 & 최근 플레이 통계">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <line x1="6" y1="12" x2="10" y2="12"></line>
        <line x1="8" y1="10" x2="8" y2="14"></line>
        <line x1="15" y1="13" x2="15.01" y2="13"></line>
        <line x1="18" y1="11" x2="18.01" y2="11"></line>
        <rect x="2" y="6" width="20" height="12" rx="4"></rect>
      </svg>
    </div>
    <div class="server-icon" onclick="switchTab('productivity')" id="rail-productivity" title="뽀모도로 집중 타이머 & 할 일 보드">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="13" r="8"></circle>
        <path d="M12 9v4l2.5 2.5"></path>
        <path d="M9 2h6"></path>
      </svg>
    </div>
    <div class="server-icon" onclick="openRecordAnalysis()" id="rail-analysis" title="모니터링 녹화 & 정밀 분석 리포트">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M3 3v18h18"></path>
        <path d="M7 15l4-5 4 3 5-7"></path>
      </svg>
    </div>
    <div class="server-icon" onclick="openAlertSettings()" id="rail-alerts" title="과열·과부하 & 장시간 플레이 스마트 경고 알림">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
        <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
      </svg>
    </div>
    <div class="server-icon" onclick="openUiSettingsModal()" id="rail-uisettings" title="원하는 하드웨어 모니터링 항목 선택 & 미니 HUD(박스형/가로바) 설정">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <line x1="4" y1="21" x2="4" y2="14"></line>
        <line x1="4" y1="10" x2="4" y2="3"></line>
        <line x1="12" y1="21" x2="12" y2="12"></line>
        <line x1="12" y1="8" x2="12" y2="3"></line>
        <line x1="20" y1="21" x2="20" y2="16"></line>
        <line x1="20" y1="12" x2="20" y2="3"></line>
        <line x1="1" y1="14" x2="7" y2="14"></line>
        <line x1="9" y1="8" x2="15" y2="8"></line>
        <line x1="17" y1="16" x2="23" y2="16"></line>
      </svg>
    </div>
    <div class="server-icon" onclick="openHelpModal()" id="rail-help" title="도움말 & 하드웨어/게이밍 이상 징후 진단 가이드 (단축키 F1)">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"></circle>
        <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path>
        <line x1="12" y1="17" x2="12.01" y2="17"></line>
      </svg>
    </div>
    <div class="server-icon" onclick="enterMiniHudMode()" id="rail-minihud" title="원클릭 컴팩트 미니 HUD 모드 전환 (항상 위 고정 • 단축키 F10)">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="3" width="18" height="18" rx="2"></rect>
        <rect x="12" y="12" width="6" height="6" rx="1"></rect>
        <path d="M8 8l3 3M11 8H8v3"></path>
      </svg>
    </div>
  </aside>

  <!-- 2. 채널 목록 사이드바 -->
  <aside class="channel-sidebar">
    <div class="server-header">
      <span style="display: inline-flex; align-items: center; gap: 8px;">
        <img src="/favicon.ico?v=3" alt="CoreFlow" width="20" height="20" style="border-radius: 5px; display: block;" />
        <span><strong style="color: var(--brand);">CORE</strong>FLOW</span>
      </span>
      <span style="color: var(--text-muted); font-size: 12px; font-weight: 500;">v__COREFLOW_APP_VERSION__</span>
    </div>

    <div class="channel-list">
      <div class="category-label">모니터링 & 스튜디오</div>
      <div class="channel-item active" id="chan-overview" onclick="switchTab('overview')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0; opacity:0.85;">
          <rect x="3" y="3" width="7" height="7" rx="1"></rect>
          <rect x="14" y="3" width="7" height="7" rx="1"></rect>
          <rect x="14" y="14" width="7" height="7" rx="1"></rect>
          <rect x="3" y="14" width="7" height="7" rx="1"></rect>
        </svg>
        <span>통합-대시보드</span>
      </div>
      <div class="channel-item" id="chan-system" onclick="switchTab('system')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0; opacity:0.85;">
          <rect x="4" y="4" width="16" height="16" rx="2"></rect>
          <rect x="9" y="9" width="6" height="6"></rect>
          <path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"></path>
        </svg>
        <span>하드웨어-GPU-상세</span>
      </div>
      <div class="channel-item" id="chan-netdisk" onclick="switchTab('netdisk')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0; opacity:0.85;">
          <ellipse cx="12" cy="5" rx="9" ry="3"></ellipse>
          <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path>
          <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path>
        </svg>
        <span>네트워크-디스크-모니터</span>
      </div>
      <div class="channel-item" id="chan-gamelog" onclick="switchTab('gamelog')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0; opacity:0.85;">
          <line x1="6" y1="12" x2="10" y2="12"></line>
          <line x1="8" y1="10" x2="8" y2="14"></line>
          <line x1="15" y1="13" x2="15.01" y2="13"></line>
          <line x1="18" y1="11" x2="18.01" y2="11"></line>
          <rect x="2" y="6" width="20" height="12" rx="4"></rect>
        </svg>
        <span>게임-플레이-기록</span>
      </div>
      <div class="channel-item" id="chan-productivity" onclick="switchTab('productivity')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0; opacity:0.85;">
          <circle cx="12" cy="13" r="8"></circle>
          <path d="M12 9v4l2.5 2.5"></path>
          <path d="M9 2h6"></path>
        </svg>
        <span>뽀모도로-할일-보드</span>
      </div>
      <div class="channel-item" id="chan-analysis" onclick="openRecordAnalysis()">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0; opacity:0.85;">
          <path d="M3 3v18h18"></path>
          <path d="M7 15l4-5 4 3 5-7"></path>
        </svg>
        <span>녹화-분석-리포트</span>
      </div>
      <div class="channel-item" id="chan-alerts" onclick="openAlertSettings()">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0; opacity:0.85;">
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
          <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
        </svg>
        <span>스마트-경고-알림</span>
      </div>
      <div class="channel-item" id="chan-uisettings" onclick="openUiSettingsModal()">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0; opacity:0.85;">
          <line x1="4" y1="21" x2="4" y2="14"></line>
          <line x1="4" y1="10" x2="4" y2="3"></line>
          <line x1="12" y1="21" x2="12" y2="12"></line>
          <line x1="12" y1="8" x2="12" y2="3"></line>
          <line x1="20" y1="21" x2="20" y2="16"></line>
          <line x1="20" y1="12" x2="20" y2="3"></line>
          <line x1="1" y1="14" x2="7" y2="14"></line>
          <line x1="9" y1="8" x2="15" y2="8"></line>
          <line x1="17" y1="16" x2="23" y2="16"></line>
        </svg>
        <span>화면·HUD-맞춤설정</span>
      </div>
      <div class="channel-item" id="chan-help" onclick="openHelpModal()">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0; opacity:0.85;">
          <circle cx="12" cy="12" r="10"></circle>
          <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path>
          <line x1="12" y1="17" x2="12.01" y2="17"></line>
        </svg>
        <span>도움말-진단-가이드</span>
      </div>

      <div class="category-label" style="margin-top: 14px;">하드웨어 엔진</div>
      <div class="voice-status-box">
        <div class="voice-status-title">
          <span class="pulse-dot"></span> 실시간 텔레메트리 활성
        </div>
        <div class="voice-status-sub" id="sidebar-gpu-name">GPU 감지 중...</div>
        <div class="voice-status-sub" id="sidebar-cpu-brand">CPU 감지 중...</div>
        <div class="voice-status-sub" id="sidebar-uptime">가동 시간 측정 중...</div>
      </div>

      <!-- 디스코드 특유의 '활동 중인 게임' 상태 카드 -->
      <div class="playing-box" id="sidebar-game-box" onclick="switchTab('gamelog')" style="cursor: pointer;" title="클릭하여 게임 플레이 기록 및 통계 메뉴 열기">
        <div class="playing-header" id="sidebar-game-header">🎮 GAME MONITOR</div>
        <div class="playing-title" id="sidebar-game-name">실행 중인 게임 없음</div>
        <div class="playing-fps" id="sidebar-game-fps" style="color: var(--text-muted);">게임 실행 시 실시간 FPS가 표시됩니다</div>
        <div class="playing-fps" id="sidebar-game-time" style="color: var(--brand); font-variant-numeric: tabular-nums; margin-top: 2px;">⏱️ 실행 시간: 00:00:00</div>
      </div>

      <!-- 윈도우 시작 시 자동 실행 옵션 스위치 -->
      <div class="startup-box" onclick="toggleStartupAutoRun()" title="클릭하여 Windows 부팅/로그인 시 이 프로그램을 자동으로 실행하도록 설정하거나 해제합니다">
        <span class="startup-label">🚀 윈도우 시작 시 자동 실행</span>
        <span class="switch-pill" id="startup-switch-pill">OFF</span>
      </div>
    </div>

    <!-- 디스코드 스타일 좌측 하단 유저 상태 바 (Windows 사용자 이름 & 프로필 사진 연동) -->
    <div class="user-panel">
      <div class="user-info" style="min-width: 0; flex: 1;">
        <div class="avatar" onclick="document.getElementById('avatar-file-input').click()" oncontextmenu="resetCustomAvatar(event)" title="좌클릭: 프로필 사진 직접 선택 / 우클릭: Windows 기본 계정 사진으로 초기화">
          <img id="user-avatar-img" src="/api/avatar" class="avatar-img" alt="Profile">
          <div class="avatar-status"></div>
        </div>
        <input type="file" id="avatar-file-input" accept="image/*" style="display:none" onchange="onUploadCustomAvatar(event)">
        <div style="min-width: 0; flex: 1;">
          <div class="user-name" id="sidebar-user-name" style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">Windows User</div>
          <div class="user-tag" id="mini-status" style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">CPU 0% • GPU 0%</div>
        </div>
      </div>
      <button class="icon-btn danger" onclick="quitApp()" title="프로그램 완전 종료">✖</button>
    </div>
  </aside>

  <!-- 3. 우측 메인 화면 -->
  <main class="main-view">
    <header class="top-bar">
      <div class="top-bar-left">
        <span style="font-size: 20px; color: var(--brand); font-weight: 700; flex-shrink: 0;">#</span>
        <span class="top-bar-title" id="top-title">통합-대시보드</span>
        <span class="top-bar-desc" id="top-desc">CPU • GPU • 게임 FPS 실시간 모니터</span>
      </div>
      <div class="top-bar-right">
        <button id="btn-record" class="rec-btn" onclick="toggleRecording()" title="클릭 시 실시간 모니터링 녹화를 시작하며, 정지 시 CSV 파일 자동 저장 및 정밀 분석 리포트를 표시합니다">
          <span class="rec-dot"></span>
          <span id="btn-record-text">녹화 시작</span>
        </button>
        <button id="btn-analysis" class="btn secondary" onclick="openRecordAnalysis()" title="녹화된 모니터링 데이터 정밀 분석 리포트 열기">
          📊 분석 리포트
        </button>
        <button id="btn-alerts" class="btn secondary" onclick="openAlertSettings()" title="GPU 과열, CPU/RAM 과부하 및 장시간 게임 플레이 스마트 경고 알림 설정">
          🔔 <span id="btn-alerts-text">스마트 알림</span>
        </button>
        <button id="btn-view-mode" class="btn secondary" onclick="toggleDashboardViewMode()" title="그래프 차트 중심 화면과 상세 수치 그리드 화면을 전환합니다">
          <span id="btn-view-mode-icon">📊</span> <span id="btn-view-mode-text">차트형</span>
        </button>
        <button id="btn-uisettings" class="btn secondary" onclick="openUiSettingsModal()" title="원하는 하드웨어 모니터링 항목만 골라 보거나 미니 HUD(박스형/가로바) 스타일을 설정합니다">
          🎛️ 화면·HUD 설정
        </button>
        <button id="btn-minihud" class="btn secondary" onclick="enterMiniHudMode()" title="창을 작게 줄이고 화면 최상단(항상 위)에 고정하는 원클릭 컴팩트 미니 HUD 모드로 전환합니다 (단축키 F10)">
          🗗 미니 HUD
        </button>
        <button id="btn-help-guide" class="btn secondary" onclick="openHelpModal()" title="각 메뉴별 수치 해석 방법, 주의해야 할 이상 징후 및 해결 팁 가이드를 엽니다 (단축키 F1)">
          ❓ 도움말
        </button>
        <button id="btn-update-check" class="btn secondary" onclick="openUpdateModal(true)" title="GitHub 저장소(neverloselkb/coreFlow)에서 최신 버전 업데이트를 확인하고 자동 설치합니다">
          🔄 <span id="btn-update-text">v__COREFLOW_APP_VERSION__</span>
        </button>
        <select id="theme-mode-select" class="select-input" onchange="onChangeThemeOverride()" title="테마 모드 선택">
          <option value="auto">🖥️ 테마 자동</option>
          <option value="light">☀️ 라이트</option>
          <option value="dark">🌙 다크</option>
        </select>
        <div class="badge" id="theme-badge" title="현재 Windows 강조 색(Accent Color)">
          <span class="accent-dot" id="accent-dot"></span>
          <span id="theme-status-text">테마 연동</span>
        </div>
      </div>
    </header>

    <div class="content-scroll">
      <!-- 실시간 스마트 경고 알림 배너 (임계치 초과 시 자동 표시) -->
      <div id="live-alert-banner" class="live-alert-banner hidden">
        <div class="live-alert-left">
          <span style="font-size: 18px; flex-shrink: 0;">🚨</span>
          <div class="live-alert-text">
            <div id="live-alert-title" style="font-weight: 800; font-size: 13.5px;">스마트 경고 감지</div>
            <div id="live-alert-desc" style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">세부 내용</div>
          </div>
        </div>
        <div style="display: flex; gap: 6px; align-items: center; flex-shrink: 0;">
          <button class="btn secondary" onclick="snoozeAlerts()" title="설정된 쿨타임 동안 경고 배너와 알림음을 일시 숨깁니다">🔕 일시 숨김</button>
          <button class="btn" onclick="openAlertSettings()">⚙️ 알림 설정</button>
        </div>
      </div>

      <!-- GitHub 새 버전 업데이트 알림 배너 -->
      <div id="update-notify-banner" class="live-alert-banner hidden" style="border-color: var(--neon-green); background: rgba(0, 200, 117, 0.12);">
        <div class="live-alert-left">
          <span style="font-size: 18px; flex-shrink: 0;">🎉</span>
          <div class="live-alert-text">
            <div id="update-banner-title" style="font-weight: 800; font-size: 13.5px; color: var(--neon-green);">새로운 CoreFlow 업데이트가 출시되었습니다!</div>
            <div id="update-banner-desc" style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">GitHub Releases에서 원클릭으로 최신 버전을 자동 다운로드 및 설치할 수 있습니다.</div>
          </div>
        </div>
        <div style="display: flex; gap: 6px; align-items: center; flex-shrink: 0;">
          <button class="btn secondary" onclick="document.getElementById('update-notify-banner').classList.add('hidden')">나중에</button>
          <button class="btn" style="background: var(--neon-green); color: #000; font-weight: 800;" onclick="openUpdateModal(false)">🚀 지금 업데이트 확인</button>
        </div>
      </div>

      <!-- 상단 하드웨어 핵심 지표 가이드 헤더 -->
      <div style="display: flex; justify-content: space-between; align-items: center; margin: 6px 4px 8px; font-size: 12px; color: var(--text-muted);">
        <span style="font-weight: 700; color: var(--text-normal); font-size: 12.5px;">⚡ 실시간 핵심 모니터링</span>
        <span style="display: inline-flex; align-items: center; gap: 4px; opacity: 0.85; font-size: 11.5px;">
          <span>💡</span> 카드를 더블클릭하면 부품별 정밀 상세 모니터링이 열립니다
        </span>
      </div>

      <!-- 상단 4열 하드웨어 & 게이밍 요약 그리드 (CPU / RAM / GPU / FPS) -->
      <section class="grid-4" id="sec-metrics">
        <!-- 1. CPU 카드 -->
        <div class="card zoom-card" id="card-metric-cpu" ondblclick="openDetailView('cpu')" title="더블클릭하여 CPU 전체 화면 상세 모니터링 열기">
          <div class="card-header">
            <div class="card-title">⚡ CPU 부하</div>
            <span class="metric-sub" id="core-count-label">0 코어</span>
          </div>
          <div style="display: flex; align-items: baseline; justify-content: space-between;">
            <div class="metric-big" id="cpu-percent" style="color: var(--brand);">0.0%</div>
          </div>
          <div class="progress-track">
            <div class="progress-fill" id="cpu-bar" style="width: 0%; background: var(--brand);"></div>
          </div>
          <canvas id="cpu-canvas" class="chart-canvas" width="320" height="80"></canvas>
          <div class="metric-num-grid" id="cpu-num-grid">
            <div class="num-cell">
              <span class="num-lbl">최근 평균</span>
              <span class="num-val" id="cpu-grid-avg">0.0%</span>
            </div>
            <div class="num-cell">
              <span class="num-lbl">최근 피크</span>
              <span class="num-val" id="cpu-grid-max">0.0%</span>
            </div>
            <div class="num-cell">
              <span class="num-lbl">가동 시간</span>
              <span class="num-val" id="cpu-grid-uptime">0시간 0분</span>
            </div>
            <div class="num-cell">
              <span class="num-lbl">프로세서</span>
              <span class="num-val" id="cpu-grid-brand" style="font-size: 11px;">-</span>
            </div>
            <div class="num-cell full-span" style="padding-top: 4px;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 3px;">
                <span class="num-lbl">논리 코어 실시간 매트릭스</span>
                <span class="num-sub" id="cpu-grid-cores-sub">0 코어</span>
              </div>
              <div class="core-mini-grid" id="cpu-grid-core-chips"></div>
            </div>
          </div>
        </div>

        <!-- 2. RAM 카드 -->
        <div class="card zoom-card" id="card-metric-mem" ondblclick="openDetailView('mem')" title="더블클릭하여 RAM 전체 화면 상세 모니터링 열기">
          <div class="card-header">
            <div class="card-title">💾 시스템 RAM</div>
            <span class="metric-sub" id="swap-label">Swap: 0 GB</span>
          </div>
          <div style="display: flex; align-items: baseline; justify-content: space-between;">
            <div class="metric-big" id="mem-percent" style="color: var(--purple);">0.0%</div>
            <div class="metric-sub" id="mem-detail">0 / 0 GB</div>
          </div>
          <div class="progress-track">
            <div class="progress-fill" id="mem-bar" style="width: 0%; background: linear-gradient(90deg, #8e44ad, #d63384);"></div>
          </div>
          <canvas id="mem-canvas" class="chart-canvas" width="320" height="80"></canvas>
          <div class="metric-num-grid" id="mem-num-grid">
            <div class="num-cell">
              <span class="num-lbl">실사용 RAM</span>
              <span class="num-val" id="mem-grid-used">0.00 GB</span>
            </div>
            <div class="num-cell">
              <span class="num-lbl">가용(여유) RAM</span>
              <span class="num-val" id="mem-grid-avail" style="color: var(--neon-green);">0.00 GB</span>
            </div>
            <div class="num-cell">
              <span class="num-lbl">전체 물리 메모리</span>
              <span class="num-val" id="mem-grid-total">0.0 GB</span>
            </div>
            <div class="num-cell">
              <span class="num-lbl">최근 평균</span>
              <span class="num-val" id="mem-grid-avg">0.0%</span>
            </div>
            <div class="num-cell full-span">
              <div style="display:flex; justify-content:space-between; align-items:center;">
                <span class="num-lbl">가상 메모리 (Pagefile / Swap)</span>
                <span class="num-val" id="mem-grid-swap" style="font-size: 11.5px;">0.0 GB</span>
              </div>
              <div class="progress-track" style="height: 5px; margin-top: 4px;">
                <div class="progress-fill" id="mem-grid-swap-bar" style="width: 0%; background: #8e44ad;"></div>
              </div>
            </div>
          </div>
        </div>

        <!-- 3. GPU 카드 (NVIDIA GeForce, AMD Radeon, Intel Arc 지원) -->
        <div class="card zoom-card" id="card-metric-gpu" ondblclick="openDetailView('gpu')" title="더블클릭하여 GPU 전체 화면 상세 모니터링 열기">
          <div class="card-header">
            <div class="card-title">🎛️ GPU</div>
            <span class="metric-sub" id="gpu-vram-detail">VRAM 0 / 0 GB</span>
          </div>
          <div style="display: flex; align-items: baseline; justify-content: space-between;">
            <div class="metric-big" id="gpu-percent" style="color: var(--orange);">0.0%</div>
          </div>
          <div class="progress-track" title="GPU 점유율">
            <div class="progress-fill" id="gpu-bar" style="width: 0%; background: linear-gradient(90deg, #ff7b00, #e53935);"></div>
          </div>
          <canvas id="gpu-canvas" class="chart-canvas" width="320" height="80"></canvas>
          <div class="stat-pills">
            <span class="stat-pill" id="gpu-power-pill">⚡ 0.0 W</span>
            <span class="stat-pill" id="gpu-clock-pill">⏱️ 0 MHz</span>
            <span class="stat-pill" id="gpu-vram-pct-pill">VRAM 0%</span>
          </div>
          <div class="metric-num-grid" id="gpu-num-grid">
            <div class="num-cell">
              <span class="num-lbl">GPU 코어 온도</span>
              <span class="num-val" id="gpu-grid-temp" style="color: var(--neon-green);">0°C</span>
            </div>
            <div class="num-cell">
              <span class="num-lbl">실시간 전력</span>
              <span class="num-val" id="gpu-grid-power">0.0 W</span>
            </div>
            <div class="num-cell">
              <span class="num-lbl">그래픽 클럭</span>
              <span class="num-val" id="gpu-grid-clock">0 MHz</span>
            </div>
            <div class="num-cell">
              <span class="num-lbl">최근 평균</span>
              <span class="num-val" id="gpu-grid-avg">0.0%</span>
            </div>
            <div class="num-cell full-span">
              <div style="display:flex; justify-content:space-between; align-items:center;">
                <span class="num-lbl">VRAM 비디오 메모리</span>
                <span class="num-val" id="gpu-grid-vram-text" style="font-size: 11.5px;">0.00 / 0.0 GB (0%)</span>
              </div>
              <div class="progress-track" style="height: 5px; margin-top: 4px;">
                <div class="progress-fill" id="gpu-grid-vram-bar" style="width: 0%; background: linear-gradient(90deg, #ff7b00, #e53935);"></div>
              </div>
            </div>
          </div>
        </div>

        <!-- 4. 게임 실시간 FPS 모니터 카드 -->
        <div class="card zoom-card" id="card-metric-fps" ondblclick="openDetailView('fps')" title="더블클릭하여 FPS 전체 화면 상세 모니터링 열기">
          <div class="card-header">
            <div class="card-title">🎮 게임 FPS</div>
            <span class="badge" id="fps-mode-badge" style="font-variant-numeric: tabular-nums;">IDLE</span>
          </div>
          <div style="display: flex; align-items: baseline; justify-content: space-between;">
            <div class="metric-big" id="fps-value" style="color: var(--neon-green);">0 FPS</div>
            <div class="metric-sub" id="fps-frametime">대기 중</div>
          </div>
          <div class="progress-track">
            <div class="progress-fill" id="fps-bar" style="width: 0%; background: linear-gradient(90deg, #23a55a, #00c875);"></div>
          </div>
          <canvas id="fps-canvas" class="chart-canvas" width="320" height="80"></canvas>
          <div class="stat-pills" style="justify-content: space-between; align-items: center;">
            <span class="stat-pill" id="fps-low-pill">1% Low: 0 FPS</span>
            <span class="stat-pill" id="fps-playtime-pill" style="font-variant-numeric: tabular-nums;">⏱️ 00:00:00</span>
            <span class="stat-pill" id="fps-target-name" style="max-width: 110px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">실행 중인 게임 없음</span>
          </div>
          <div class="metric-num-grid" id="fps-num-grid">
            <div class="num-cell">
              <span class="num-lbl">1% Low FPS</span>
              <span class="num-val" id="fps-grid-low" style="color: var(--neon-green);">0 FPS</span>
            </div>
            <div class="num-cell">
              <span class="num-lbl">프레임 타임</span>
              <span class="num-val" id="fps-grid-ms">0.0 ms</span>
            </div>
            <div class="num-cell">
              <span class="num-lbl">평균 FPS</span>
              <span class="num-val" id="fps-grid-avg">0 FPS</span>
            </div>
            <div class="num-cell">
              <span class="num-lbl">최근 피크 FPS</span>
              <span class="num-val" id="fps-grid-max">0 FPS</span>
            </div>
            <div class="num-cell full-span">
              <div style="display:flex; justify-content:space-between; align-items:center;">
                <span class="num-lbl">실행 게임 및 세션</span>
                <span class="num-val" id="fps-grid-playtime" style="font-size: 11.5px; color: var(--brand);">⏱️ 00:00:00</span>
              </div>
              <div class="num-val" id="fps-grid-gamename" style="font-size: 11px; margin-top: 3px; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">실행 중인 게임 없음</div>
            </div>
          </div>
        </div>
      </section>

      <!-- 통합 대시보드 전용: 실시간 네트워크(다운로드/업로드/핑) & 디스크(I/O/용량) 한눈에 보기 바 -->
      <section class="card" id="sec-netdisk-strip" onclick="switchTab('netdisk')" style="padding: 9px 14px; flex-shrink: 0; cursor: pointer;" title="클릭하여 실시간 네트워크(속도/핑) & 디스크(용량/I/O) 전용 모니터 열기">
        <div class="strip-chart-view" style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;">
          <div style="display: flex; align-items: center; gap: 14px; flex-wrap: wrap; min-width: 0;">
            <span style="font-size: 12px; font-weight: 800; color: var(--cyan); display: inline-flex; align-items: center; gap: 5px;">
              🌐 <span id="strip-net-down">↓ 0.00 MB/s</span>
            </span>
            <span style="font-size: 12px; font-weight: 800; color: var(--brand); display: inline-flex; align-items: center; gap: 5px;">
              📤 <span id="strip-net-up">↑ 0.00 MB/s</span>
            </span>
            <span style="font-size: 12px; font-weight: 800; color: var(--neon-green); display: inline-flex; align-items: center; gap: 5px;" id="strip-ping-wrap">
              📡 <span id="strip-net-ping">Ping 0.0 ms</span>
            </span>
            <span style="font-size: 12px; font-weight: 700; color: var(--orange); display: inline-flex; align-items: center; gap: 5px;">
              💽 <span id="strip-disk-io">디스크 R 0.00 / W 0.00 MB/s</span>
            </span>
            <span style="font-size: 11.5px; color: var(--text-muted); font-variant-numeric: tabular-nums;" id="strip-disk-summary">
              드라이브 스캔 중...
            </span>
          </div>
          <span class="badge" style="color: var(--brand);">네트워크·디스크 상세 보기 ➔</span>
        </div>
        <div class="strip-grid-view" style="display: none; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 8px;">
          <div class="num-cell">
            <span class="num-lbl">🌐 다운로드</span>
            <span class="num-val" id="strip-grid-down" style="color: var(--cyan);">0.00 MB/s</span>
            <span class="num-sub" id="strip-grid-down-sub">0.0 Mbps</span>
          </div>
          <div class="num-cell">
            <span class="num-lbl">📤 업로드</span>
            <span class="num-val" id="strip-grid-up" style="color: var(--brand);">0.00 MB/s</span>
            <span class="num-sub" id="strip-grid-up-sub">0.0 Mbps</span>
          </div>
          <div class="num-cell">
            <span class="num-lbl">📡 게임 서버 핑</span>
            <span class="num-val" id="strip-grid-ping" style="color: var(--neon-green);">0.0 ms</span>
            <span class="num-sub" id="strip-grid-ping-sub">Jitter 0.0 ms</span>
          </div>
          <div class="num-cell">
            <span class="num-lbl">💽 디스크 I/O</span>
            <span class="num-val" id="strip-grid-disk-io" style="color: var(--orange);">0.00 MB/s</span>
            <span class="num-sub" id="strip-grid-disk-sub">R 0.00 / W 0.00</span>
          </div>
          <div class="num-cell">
            <span class="num-lbl">💾 드라이브 볼륨</span>
            <span class="num-val" id="strip-grid-drives" style="font-size: 11px;">스캔 중...</span>
            <span class="num-sub" id="strip-grid-drives-sub">여유 공간</span>
          </div>
        </div>
      </section>

      <!-- 코어별 상세 바 (하드웨어 상세 탭 전용) -->
      <section class="card hidden" id="sec-cores">
        <div class="card-header">
          <div class="card-title">🧩 논리 코어별 실시간 부하</div>
        </div>
        <div class="cores-grid" id="cores-container"></div>
      </section>

      <!-- 하단 메인 분할 영역 -->
      <section class="grid-main" id="sec-bottom">
        <!-- 좌측: 상위 프로세스 목록 -->
        <div class="card" id="card-processes" style="min-height: 0; height: 100%;">
          <div class="card-header">
            <div class="card-title">📊 실시간 상위 프로세스</div>
            <div style="display: flex; gap: 6px; align-items: center;">
              <select id="game-select" class="select-input" onchange="onSelectTargetProcess()" title="FPS 모니터링 대상 선택">
                <option value="auto">🎯 게임 자동 감지</option>
              </select>
              <button class="btn secondary" onclick="openGameScanModal()" title="실행 중인 게임 프로세스 자동 탐색 및 수동 등록" style="white-space:nowrap; padding: 4px 10px; font-size: 12px;">🔍 게임 탐색</button>
              <input type="text" id="proc-search" class="search-input" placeholder="프로세스 검색..." oninput="renderProcesses()">
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th id="th-pid" onclick="toggleSort('pid')">PID</th>
                  <th id="th-name" onclick="toggleSort('name')">프로세스 이름</th>
                  <th id="th-cpu" onclick="toggleSort('cpu')">CPU</th>
                  <th id="th-mem_mb" class="active-sort" onclick="toggleSort('mem_mb')">메모리 (MB) ▼</th>
                </tr>
              </thead>
              <tbody id="proc-tbody"></tbody>
            </table>
          </div>
        </div>

        <!-- 우측: 뽀모도로 타이머 & 할 일 목록 -->
        <div style="display: flex; flex-direction: column; gap: 14px; min-height: 0; height: 100%;" id="card-productivity">
          <!-- 뽀모도로 카드 -->
          <div class="card" style="flex-shrink: 0;">
            <div class="card-header">
              <div class="card-title" id="pomo-mode-title">🍅 뽀모도로 집중 타이머 (25분)</div>
              <span class="badge" id="pomo-status-badge">대기 중</span>
            </div>
            <div class="pomo-box">
              <div>
                <div class="pomo-time" id="pomo-time-display">25:00</div>
                <div class="metric-sub" id="pomo-sub-text">집중 세션을 시작해 보세요!</div>
              </div>
              <div class="btn-group">
                <button class="btn" id="pomo-start-btn" onclick="togglePomodoro()">시작</button>
                <button class="btn secondary" onclick="resetPomodoro()">리셋</button>
                <button class="btn secondary" onclick="switchPomodoroMode()">집중/휴식 전환</button>
              </div>
            </div>
            <div class="progress-track">
              <div class="progress-fill" id="pomo-bar" style="width: 0%; background-color: var(--brand);"></div>
            </div>
          </div>

          <!-- 할 일 (Todo) 카드 -->
          <div class="card" style="flex: 1 1 0; min-height: 0;">
            <div class="card-header">
              <div class="card-title">📝 오늘 할 일 보드 (Todo)</div>
              <span class="metric-sub" id="todo-counter">0개 완료</span>
            </div>
            <div class="todo-input-row">
              <input type="text" id="todo-input" class="todo-input" placeholder="새로운 할 일을 입력하고 Enter를 누르세요..." onkeydown="if(event.key==='Enter') addTodo()">
              <button class="btn" onclick="addTodo()">추가</button>
            </div>
            <div class="todo-list" id="todo-list"></div>
          </div>
        </div>
      </section>

      <!-- 게임 플레이 기록 & 최근 많이 한 게임 통계 전용 뷰 -->
      <section class="gamelog-view hidden" id="sec-gamelog">
        <div class="grid-4">
          <div class="card">
            <div class="card-header">
              <div class="card-title">🎮 현재 실행 게임</div>
              <span class="badge" id="gl-active-badge">IDLE</span>
            </div>
            <div style="display: flex; align-items: baseline; justify-content: space-between; gap: 6px; min-width: 0;">
              <div class="metric-big" id="gl-active-timer" style="color: var(--neon-green);">00:00:00</div>
              <div class="metric-sub" id="gl-active-fps">대기 중</div>
            </div>
            <div class="metric-sub" id="gl-active-name" style="font-weight: 700; color: var(--text-normal);">실행 중인 게임 없음</div>
          </div>

          <div class="card">
            <div class="card-header">
              <div class="card-title">🏆 최다 플레이 게임</div>
              <span class="badge" id="gl-top-share-badge">점유율 0%</span>
            </div>
            <div style="display: flex; align-items: baseline; justify-content: space-between; gap: 6px; min-width: 0;">
              <div class="metric-big" id="gl-top-game-name" style="color: #f59f00;">기록 없음</div>
            </div>
            <div class="metric-sub" id="gl-top-game-time" style="font-variant-numeric: tabular-nums;">누적 00:00:00 (0회)</div>
          </div>

          <div class="card">
            <div class="card-header">
              <div class="card-title">⏱️ 오늘 / 7일 플레이</div>
              <span class="badge">시:분:초</span>
            </div>
            <div style="display: flex; align-items: baseline; justify-content: space-between; gap: 6px; min-width: 0;">
              <div class="metric-big" id="gl-today-time" style="color: var(--brand);">00:00:00</div>
              <div class="metric-sub">오늘 누적</div>
            </div>
            <div class="metric-sub" id="gl-week-time" style="font-variant-numeric: tabular-nums;">최근 7일: 00:00:00</div>
          </div>

          <div class="card">
            <div class="card-header">
              <div class="card-title">📚 전체 누적 로그</div>
              <span class="badge" id="gl-total-games-badge">0개 게임</span>
            </div>
            <div style="display: flex; align-items: baseline; justify-content: space-between; gap: 6px; min-width: 0;">
              <div class="metric-big" id="gl-total-time" style="color: var(--purple);">00:00:00</div>
              <div class="metric-sub" id="gl-total-sessions">총 0회</div>
            </div>
            <div class="metric-sub">logs/game_play_log.tsv</div>
          </div>
        </div>

        <div class="grid-main" style="grid-template-columns: minmax(0, 1fr) minmax(0, 1.25fr);">
          <!-- 좌측: 최근 많이 플레이한 게임 랭킹 보드 -->
          <div class="card" style="min-height: 0; height: 100%;">
            <div class="card-header">
              <div class="card-title">🔥 최근 가장 많이 플레이한 게임 랭킹</div>
              <div class="filter-pills">
                <button class="filter-pill active" id="gl-period-7d" onclick="setGameLogPeriod('7d')">최근 7일</button>
                <button class="filter-pill" id="gl-period-30d" onclick="setGameLogPeriod('30d')">30일</button>
                <button class="filter-pill" id="gl-period-today" onclick="setGameLogPeriod('today')">오늘</button>
                <button class="filter-pill" id="gl-period-all" onclick="setGameLogPeriod('all')">전체</button>
              </div>
            </div>
            <div class="rank-list" id="gamelog-ranking-list"></div>
          </div>

          <!-- 우측: 상세 세션 히스토리 로그 테이블 -->
          <div class="card" style="min-height: 0; height: 100%;">
            <div class="card-header">
              <div class="card-title">🕒 게임 플레이 세션 히스토리 (시:분:초 로그)</div>
              <div style="display: flex; gap: 6px; align-items: center;">
                <input type="text" id="gamelog-search" class="search-input" placeholder="게임 이름 검색..." oninput="renderGameLogDashboard()" style="width: 150px;">
                <button class="btn secondary" onclick="openGameScanModal()" title="실행 중인 게임 프로세스 자동 탐색 및 수동 등록">🔍 게임 탐색</button>
                <button class="btn secondary" onclick="openLogsFolder()" title="게임 플레이 로그 파일(logs/game_play_log.tsv)이 저장된 폴더 열기">📂 폴더</button>
                <button class="btn secondary" onclick="clearAllGameLogs()" title="저장된 모든 게임 플레이 로그 기록 초기화">🗑️ 초기화</button>
              </div>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th style="cursor:default">플레이 일시 (시작 ~ 종료)</th>
                    <th style="cursor:default">게임 이름</th>
                    <th style="cursor:default">실행 시간 (시:분:초)</th>
                    <th style="cursor:default">평균 FPS / 1% Low</th>
                    <th style="cursor:default">최고 GPU 온도 / 피크 부하</th>
                    <th style="cursor:default; text-align:right;">관리</th>
                  </tr>
                </thead>
                <tbody id="gamelog-tbody"></tbody>
              </table>
            </div>
          </div>
        </div>
      </section>

      <!-- 실시간 네트워크(다운로드/업로드/핑) & 디스크(용량/I/O) 전용 모니터 뷰 -->
      <section class="gamelog-view hidden" id="sec-netdisk">
        <!-- 상단 4열 실시간 네트워크 & 디스크 I/O 카드 -->
        <div class="grid-4">
          <!-- 1. 실시간 다운로드 속도 -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">🌐 실시간 다운로드</div>
              <span class="badge" id="nd-iface-badge">Ethernet</span>
            </div>
            <div style="display: flex; align-items: baseline; justify-content: space-between; gap: 6px; min-width: 0;">
              <div class="metric-big" id="nd-rx-mbs" style="color: var(--cyan);">0.00 MB/s</div>
              <div class="metric-sub" id="nd-rx-mbps">0.0 Mbps</div>
            </div>
            <canvas id="nd-rx-canvas" class="chart-canvas" width="320" height="72"></canvas>
            <div class="stat-pills" style="justify-content: space-between;">
              <span class="stat-pill" id="nd-rx-peak-pill">최고: 0.00 MB/s</span>
              <span class="stat-pill" id="nd-rx-total-pill">누적 수신: 0.00 GB</span>
            </div>
          </div>

          <!-- 2. 실시간 업로드 속도 -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">📤 실시간 업로드</div>
              <span class="badge">TX Stream</span>
            </div>
            <div style="display: flex; align-items: baseline; justify-content: space-between; gap: 6px; min-width: 0;">
              <div class="metric-big" id="nd-tx-mbs" style="color: var(--brand);">0.00 MB/s</div>
              <div class="metric-sub" id="nd-tx-mbps">0.0 Mbps</div>
            </div>
            <canvas id="nd-tx-canvas" class="chart-canvas" width="320" height="72"></canvas>
            <div class="stat-pills" style="justify-content: space-between;">
              <span class="stat-pill" id="nd-tx-peak-pill">최고: 0.00 MB/s</span>
              <span class="stat-pill" id="nd-tx-total-pill">누적 송신: 0.00 GB</span>
            </div>
          </div>

          <!-- 3. 실시간 네트워크 핑 (Ping & Jitter) -->
          <div class="card">
            <div class="card-header">
              <div class="card-title" id="nd-ping-card-title">📡 네트워크 핑 (Ping)</div>
              <span class="badge" id="nd-ping-status-badge" style="color: var(--neon-green);">쾌적 🟢</span>
            </div>
            <div style="display: flex; align-items: baseline; justify-content: space-between; gap: 6px; min-width: 0;">
              <div class="metric-big" id="nd-ping-ms" style="color: var(--neon-green);">0.0 ms</div>
              <div class="metric-sub" id="nd-jitter-ms">Jitter: 0.0 ms</div>
            </div>
            <canvas id="nd-ping-canvas" class="chart-canvas" width="320" height="72"></canvas>
            <div class="stat-pills" style="justify-content: space-between;">
              <span class="stat-pill" id="nd-ping-avg-pill">60초 평균: 0.0 ms</span>
              <span class="stat-pill" id="nd-ping-target-pill">1.1.1.1</span>
            </div>
          </div>

          <!-- 4. 실시간 디스크 I/O (Read / Write) -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">💽 실시간 디스크 I/O</div>
              <span class="badge" id="nd-disk-count-badge">0개 드라이브</span>
            </div>
            <div style="display: flex; align-items: baseline; justify-content: space-between; gap: 6px; min-width: 0;">
              <div class="metric-big" id="nd-disk-total-mbs" style="color: var(--orange);">0.00 MB/s</div>
              <div class="metric-sub" id="nd-disk-rw-sub">R 0.0 / W 0.0</div>
            </div>
            <canvas id="nd-disk-canvas" class="chart-canvas" width="320" height="72"></canvas>
            <div class="stat-pills" style="justify-content: space-between;">
              <span class="stat-pill" id="nd-disk-read-pill" style="color: var(--neon-green);">읽기(R): 0.00 MB/s</span>
              <span class="stat-pill" id="nd-disk-write-pill" style="color: var(--orange);">쓰기(W): 0.00 MB/s</span>
            </div>
          </div>
        </div>

        <!-- 하단 2열: 좌측 로컬 드라이브 용량 보드 / 우측 디스크 I/O 상위 프로세스 & 네트워크 인터페이스 -->
        <div class="grid-main" style="grid-template-columns: minmax(0, 1.05fr) minmax(0, 1.2fr);">
          <!-- 좌측: 드라이브별 용량 및 상태 -->
          <div class="card" style="min-height: 0; height: 100%;">
            <div class="card-header">
              <div class="card-title">💽 로컬 디스크 드라이브 용량 및 여유 공간</div>
              <span class="badge" id="nd-total-storage-badge">전체 용량 계산 중...</span>
            </div>
            <div class="rank-list" id="nd-drives-list"></div>
          </div>

          <!-- 우측: 실시간 디스크 I/O 상위 프로세스 & 네트워크 어댑터 상세 -->
          <div class="card" style="min-height: 0; height: 100%;">
            <div class="card-header">
              <div class="card-title">🔥 실시간 디스크 I/O 상위 프로세스 & 네트워크 어댑터</div>
              <span class="badge">실시간 Read / Write 추적</span>
            </div>
            <div id="nd-ifaces-summary" style="display: flex; flex-wrap: wrap; gap: 6px; flex-shrink: 0;"></div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th style="cursor:default">PID</th>
                    <th style="cursor:default">프로세스 이름</th>
                    <th style="cursor:default">디스크 읽기 (MB/s)</th>
                    <th style="cursor:default">디스크 쓰기 (MB/s)</th>
                    <th style="cursor:default">CPU / RAM</th>
                  </tr>
                </thead>
                <tbody id="nd-disk-procs-tbody"></tbody>
              </table>
            </div>
          </div>
        </div>
      </section>
    </div>
  </main>

  <!-- 전체 화면 상세 모니터링 뷰 (카드 더블 클릭 시 표시) -->
  <div id="detail-overlay" class="detail-overlay hidden">
    <div class="detail-header">
      <div class="detail-title-wrap">
        <span id="detail-title" class="detail-title">⚡ CPU 상세 모니터링</span>
        <span id="detail-sub" class="detail-sub">실시간 60초 정밀 분석</span>
      </div>
      <div style="display: flex; align-items: center; gap: 8px;">
        <button class="btn secondary" id="btn-detail-view-mode" onclick="toggleDashboardViewMode()" title="차트 그래프 화면과 정밀 수치 그리드 화면을 전환합니다">
          <span id="btn-detail-view-mode-icon">📊</span> <span id="btn-detail-view-mode-text">차트형</span>
        </button>
        <button class="btn ghost" id="dt-btn-cpu" onclick="openDetailView('cpu')">⚡ CPU</button>
        <button class="btn ghost" id="dt-btn-mem" onclick="openDetailView('mem')">💾 RAM</button>
        <button class="btn ghost" id="dt-btn-gpu" onclick="openDetailView('gpu')">🎛️ GPU</button>
        <button class="btn ghost" id="dt-btn-fps" onclick="openDetailView('fps')">🎮 FPS</button>
        <button class="btn" onclick="closeDetailView()">↙ 대시보드로 돌아가기 (Esc / 더블클릭)</button>
      </div>
    </div>
    <div class="detail-body" ondblclick="closeDetailView()" title="빈 영역을 더블 클릭하거나 Esc 키를 누르면 원래 화면으로 돌아갑니다">
      <div id="detail-kpi-grid" class="kpi-grid"></div>
      <div class="detail-chart-wrap" id="detail-chart-wrap">
        <div class="detail-chart-head">
          <span id="detail-chart-title" style="font-size: 13px; font-weight: 700; color: var(--text-header);">실시간 60초 추이 그래프</span>
          <span id="detail-chart-scale" class="badge">Scale: 0 ~ 100%</span>
        </div>
        <canvas id="detail-main-canvas" class="detail-canvas" width="1100" height="270"></canvas>
      </div>
      <div id="detail-grid-panel" class="detail-grid-panel"></div>
      <div id="detail-extra-panel" class="card" style="gap: 12px;"></div>
    </div>
  </div>

  <!-- 모니터링 녹화 데이터 정밀 분석 리포트 오버레이 -->
  <div id="record-overlay" class="detail-overlay hidden">
    <div class="detail-header">
      <div class="detail-title-wrap">
        <span class="detail-title">📊 모니터링 녹화 정밀 분석 리포트</span>
        <span id="rec-meta-sub" class="detail-sub">녹화 버튼을 눌러 구간 데이터를 수집하거나 기존 CSV 파일을 불러와 분석할 수 있습니다</span>
      </div>
      <div style="display: flex; align-items: center; gap: 8px;">
        <button id="rec-modal-btn" class="rec-btn" onclick="toggleRecording()">
          <span class="rec-dot"></span>
          <span id="rec-modal-btn-text">새 녹화 시작</span>
        </button>
        <button class="btn secondary" onclick="openLogsFolder()" title="저장된 CSV 파일이 있는 logs 폴더를 탐색기에서 엽니다">📂 저장 폴더 열기</button>
        <button class="btn secondary" onclick="downloadCurrentCsv()" title="현재 분석 중인 녹화 데이터를 CSV 파일로 다운로드합니다">💾 CSV 다운로드</button>
        <button class="btn secondary" onclick="document.getElementById('csv-file-input').click()" title="이전에 저장된 모니터링 CSV 파일을 불러와 분석합니다">📥 CSV 불러오기</button>
        <input type="file" id="csv-file-input" accept=".csv" style="display:none" onchange="onLoadCsvFile(event)">
        <button class="btn" onclick="closeRecordAnalysis()">↙ 대시보드로 돌아가기 (Esc)</button>
      </div>
    </div>
    <div class="detail-body">
      <!-- 저장된 파일 경로 안내 바 -->
      <div id="rec-saved-banner" class="scrub-inspector" style="border-left: 4px solid var(--green);">
        <span id="rec-saved-path-text">💡 상단 <strong>[모니터링 녹화]</strong>를 누르면 실시간 수집이 시작되고, <strong>[정지]</strong>를 누르면 자동으로 <code>logs/</code> 폴더에 CSV 파일이 저장되며 이 분석 리포트가 갱신됩니다.</span>
        <span id="rec-sample-badge" class="badge">샘플 0개</span>
      </div>

      <!-- 자동 병목 & 성능 진단 인사이트 4열 그리드 -->
      <div id="rec-insight-grid" class="insight-grid"></div>

      <!-- 녹화 전체 구간 인터랙티브 멀티 타임라인 그래프 -->
      <div class="detail-chart-wrap">
        <div class="detail-chart-head">
          <div style="display:flex; align-items:center; gap:10px;">
            <span style="font-size: 13px; font-weight: 700; color: var(--text-header);">📈 녹화 전 구간 멀티 타임라인 비교 그래프 (마우스를 올려 시점별 상세 수치 확인)</span>
          </div>
          <div class="series-toggles">
            <span class="series-pill active" id="sp-cpu" onclick="toggleRecSeries('cpu')"><span style="color:var(--brand)">●</span> CPU (%)</span>
            <span class="series-pill active" id="sp-mem" onclick="toggleRecSeries('mem')"><span style="color:var(--purple)">●</span> RAM (%)</span>
            <span class="series-pill active" id="sp-gpu" onclick="toggleRecSeries('gpu')"><span style="color:var(--orange)">●</span> GPU (%)</span>
            <span class="series-pill active" id="sp-temp" onclick="toggleRecSeries('temp')"><span style="color:var(--red)">●</span> GPU 온도 (°C)</span>
            <span class="series-pill active" id="sp-fps" onclick="toggleRecSeries('fps')"><span style="color:var(--neon-green)">●</span> 게임 FPS</span>
          </div>
        </div>
        <canvas id="rec-timeline-canvas" class="detail-canvas" width="1100" height="250" onmousemove="onScrubTimeline(event)" onmouseleave="onLeaveTimeline()"></canvas>
        <div id="rec-scrub-info" class="scrub-inspector">
          <span>🖱️ 그래프 위에 마우스를 움직이면 해당 시점의 정확한 하드웨어 수치와 상위 점유 프로세스를 확인할 수 있습니다.</span>
        </div>
      </div>

      <!-- 구간 정밀 통계 비교 테이블 -->
      <div class="card" style="gap: 10px;">
        <div class="card-header">
          <div class="card-title">📋 녹화 구간 항목별 정밀 통계 요약 (평균 / 최고 Peak / 최저 Min / 피크 발생 시각)</div>
        </div>
        <div class="table-wrap" style="max-height: 280px;">
          <table>
            <thead>
              <tr>
                <th style="cursor:default">모니터링 항목</th>
                <th style="cursor:default">구간 평균 (Avg)</th>
                <th style="cursor:default">구간 최고 (Peak)</th>
                <th style="cursor:default">최고치 발생 시각</th>
                <th style="cursor:default">구간 최저 (Min)</th>
                <th style="cursor:default">상태 및 안정성 평가</th>
              </tr>
            </thead>
            <tbody id="rec-stats-tbody"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- 스마트 경고 알림 설정 및 히스토리 오버레이 -->
  <div id="alert-overlay" class="detail-overlay hidden">
    <div class="detail-header">
      <div class="detail-title-group">
        <div class="detail-title">🔔 과열·과부하 & 장시간 게임 플레이 스마트 경고 설정</div>
        <div class="detail-sub">GPU 온도 • CPU/RAM/VRAM 과부하 • 연속 게임 플레이 시간 임계치 맞춤형 감시 및 실시간 경고 로그</div>
      </div>
      <div class="detail-actions">
        <button class="btn ghost" onclick="playAlertBeep(true)">🔊 경고음 테스트</button>
        <button class="btn ghost" onclick="testSmartAlert()">🧪 가상 경고 발동 테스트</button>
        <button class="btn ghost" onclick="resetAlertConfig()">🔄 기본값 복원</button>
        <button class="btn" onclick="closeAlertSettings()">↙ 대시보드로 돌아가기 (Esc)</button>
      </div>
    </div>

    <div class="detail-body">
      <!-- 상단 전역 알림 제어 카드 -->
      <div class="card" style="padding: 14px 16px;">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
          <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
            <span id="alert-global-status-badge" class="badge" style="color: var(--neon-green); font-size: 12px; padding: 5px 10px;">🟢 실시간 스마트 감시 작동 중</span>
            <span style="font-size: 12px; color: var(--text-muted);">설정한 임계치를 초과하면 상단 경고 배너, 토스트 메시지, 경고 비프음으로 즉시 알려줍니다.</span>
          </div>
          <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
            <label style="display: flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 700; cursor: pointer; background: var(--bg-tertiary); padding: 6px 10px; border-radius: 6px; border: 1px solid var(--border);">
              <input type="checkbox" id="alert-sound-chk" onchange="onUpdateAlertConfig()" style="accent-color: var(--brand); cursor: pointer;" />
              🔊 경고 비프음(사운드) 재생
            </label>
            <div style="display: flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 700; background: var(--bg-tertiary); padding: 4px 10px; border-radius: 6px; border: 1px solid var(--border);">
              <span>⏱️ 재알림 쿨타임:</span>
              <select id="alert-cooldown-sel" class="proc-select" onchange="onUpdateAlertConfig()" style="padding: 2px 6px;">
                <option value="60">1분마다</option>
                <option value="180">3분마다</option>
                <option value="300">5분마다</option>
                <option value="600">10분마다</option>
                <option value="1800">30분마다</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      <!-- 5대 스마트 경고 규칙 설정 그리드 -->
      <div class="alert-rules-grid">
        <!-- 1. GPU 온도 과열 경고 -->
        <div class="alert-rule-card">
          <div class="alert-rule-top">
            <span class="alert-rule-title">🌡️ GPU 코어 과열 경고</span>
            <label style="display:flex; align-items:center; gap:5px; font-size:12px; font-weight:700; cursor:pointer;">
              <input type="checkbox" id="rule-gpu-temp-on" onchange="onUpdateAlertConfig()" style="accent-color:var(--brand);" /> 감시 켜기
            </label>
          </div>
          <div style="display:flex; justify-content:space-between; align-items:baseline;">
            <span style="font-size:12px; color:var(--text-muted);">경고 기준 온도</span>
            <strong id="rule-gpu-temp-label" style="font-size:18px; color:var(--red);">78°C 이상</strong>
          </div>
          <input type="range" id="rule-gpu-temp-val" class="range-slider" min="60" max="95" step="1" oninput="onUpdateAlertConfig()" />
          <div style="display:flex; justify-content:space-between; font-size:11px; color:var(--text-muted);">
            <span>60°C</span>
            <span id="live-rule-gpu-temp">현재 GPU 온도: --°C</span>
            <span>95°C</span>
          </div>
        </div>

        <!-- 2. 시스템 RAM 부족 경고 -->
        <div class="alert-rule-card">
          <div class="alert-rule-top">
            <span class="alert-rule-title">💾 시스템 RAM 과부하 경고</span>
            <label style="display:flex; align-items:center; gap:5px; font-size:12px; font-weight:700; cursor:pointer;">
              <input type="checkbox" id="rule-ram-on" onchange="onUpdateAlertConfig()" style="accent-color:var(--brand);" /> 감시 켜기
            </label>
          </div>
          <div style="display:flex; justify-content:space-between; align-items:baseline;">
            <span style="font-size:12px; color:var(--text-muted);">경고 기준 점유율</span>
            <strong id="rule-ram-label" style="font-size:18px; color:var(--purple);">90% 이상</strong>
          </div>
          <input type="range" id="rule-ram-val" class="range-slider" min="70" max="98" step="1" oninput="onUpdateAlertConfig()" />
          <div style="display:flex; justify-content:space-between; font-size:11px; color:var(--text-muted);">
            <span>70%</span>
            <span id="live-rule-ram">현재 RAM 점유율: --%</span>
            <span>98%</span>
          </div>
        </div>

        <!-- 3. 그래픽 VRAM 포화 경고 -->
        <div class="alert-rule-card">
          <div class="alert-rule-top">
            <span class="alert-rule-title">🎛️ 그래픽 VRAM 포화 경고</span>
            <label style="display:flex; align-items:center; gap:5px; font-size:12px; font-weight:700; cursor:pointer;">
              <input type="checkbox" id="rule-vram-on" onchange="onUpdateAlertConfig()" style="accent-color:var(--brand);" /> 감시 켜기
            </label>
          </div>
          <div style="display:flex; justify-content:space-between; align-items:baseline;">
            <span style="font-size:12px; color:var(--text-muted);">경고 기준 VRAM 점유율</span>
            <strong id="rule-vram-label" style="font-size:18px; color:var(--orange);">92% 이상</strong>
          </div>
          <input type="range" id="rule-vram-val" class="range-slider" min="70" max="99" step="1" oninput="onUpdateAlertConfig()" />
          <div style="display:flex; justify-content:space-between; font-size:11px; color:var(--text-muted);">
            <span>70%</span>
            <span id="live-rule-vram">현재 VRAM 점유율: --%</span>
            <span>99%</span>
          </div>
        </div>

        <!-- 4. CPU 고부하 지속 경고 -->
        <div class="alert-rule-card">
          <div class="alert-rule-top">
            <span class="alert-rule-title">⚡ CPU 고부하 지속 경고 (5초 연속)</span>
            <label style="display:flex; align-items:center; gap:5px; font-size:12px; font-weight:700; cursor:pointer;">
              <input type="checkbox" id="rule-cpu-on" onchange="onUpdateAlertConfig()" style="accent-color:var(--brand);" /> 감시 켜기
            </label>
          </div>
          <div style="display:flex; justify-content:space-between; align-items:baseline;">
            <span style="font-size:12px; color:var(--text-muted);">5초 연속 초과 기준</span>
            <strong id="rule-cpu-label" style="font-size:18px; color:var(--brand);">90% 이상</strong>
          </div>
          <input type="range" id="rule-cpu-val" class="range-slider" min="70" max="99" step="1" oninput="onUpdateAlertConfig()" />
          <div style="display:flex; justify-content:space-between; font-size:11px; color:var(--text-muted);">
            <span>70%</span>
            <span id="live-rule-cpu">현재 CPU 사용률: --%</span>
            <span>99%</span>
          </div>
        </div>

        <!-- 5. 장시간 게임 플레이 건강 알림 -->
        <div class="alert-rule-card">
          <div class="alert-rule-top">
            <span class="alert-rule-title">⏰ 장시간 게임 플레이 휴식 알림</span>
            <label style="display:flex; align-items:center; gap:5px; font-size:12px; font-weight:700; cursor:pointer;">
              <input type="checkbox" id="rule-playtime-on" onchange="onUpdateAlertConfig()" style="accent-color:var(--brand);" /> 감시 켜기
            </label>
          </div>
          <div style="display:flex; justify-content:space-between; align-items:baseline;">
            <span style="font-size:12px; color:var(--text-muted);">연속 플레이 알림 기준</span>
            <strong id="rule-playtime-label" style="font-size:18px; color:var(--neon-green);">120분 (2시간)</strong>
          </div>
          <input type="range" id="rule-playtime-val" class="range-slider" min="30" max="300" step="30" oninput="onUpdateAlertConfig()" />
          <div style="display:flex; justify-content:space-between; font-size:11px; color:var(--text-muted);">
            <span>30분</span>
            <span id="live-rule-playtime">현재 게임 실행: 00:00:00</span>
            <span>300분(5시간)</span>
          </div>
        </div>
      </div>

      <!-- 스마트 경고 발생 히스토리 로그 테이블 -->
      <div class="card" style="padding: 14px 16px; flex-shrink: 0;">
        <div class="card-header">
          <div style="display:flex; align-items:center; gap:8px;">
            <span class="card-title">📋 스마트 경고 발생 히스토리 로그</span>
            <span id="alert-history-count-badge" class="badge">0건</span>
          </div>
          <button class="btn ghost" onclick="clearAlertHistory()" style="font-size:11px; padding:4px 10px;">🗑️ 경고 기록 비우기</button>
        </div>
        <div class="table-wrap" style="min-height: 180px; max-height: 320px; overflow-y: auto; flex: none;">
          <table>
            <thead>
              <tr>
                <th style="cursor:default; width: 145px;">발생 시각</th>
                <th style="cursor:default; width: 170px;">경고 항목</th>
                <th style="cursor:default;">감지 수치 / 임계치</th>
                <th style="cursor:default;">당시 실행 게임 / 상위 부하 프로세스</th>
              </tr>
            </thead>
            <tbody id="alert-history-tbody"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- 원클릭 컴팩트 미니 HUD 모드 전용 뷰 -->
  <div id="mini-hud-overlay" class="mini-hud-overlay hidden" ondblclick="exitMiniHudMode()" title="빈 영역 더블클릭 또는 Esc / F10 키로 원래 창 크기로 복귀">
    <div class="mini-hud-bar" ondblclick="event.stopPropagation()">
      <div style="display:flex; align-items:center; gap:6px; min-width:0; flex:1;">
        <img src="/favicon.ico?v=3" width="15" height="15" style="border-radius:3px; flex-shrink:0;" alt="CF" />
        <span style="font-size:11px; font-weight:900; letter-spacing:0.3px; flex-shrink:0;"><strong style="color:var(--brand)">CORE</strong>HUD</span>
        <span id="mh-game-badge" class="badge" style="font-size:10px; padding:2px 6px; overflow:hidden; text-overflow:ellipsis;">IDLE 대기</span>
      </div>
      <div style="display:flex; align-items:center; gap:4px; flex-shrink:0;">
        <button id="mh-topmost-btn" class="mini-btn active" onclick="toggleMiniHudTopmost()" title="다른 창이나 창모드 게임 위에 항상 고정(Topmost)할지 선택합니다">📌 항상 위 ON</button>
        <button id="mh-layout-btn" class="mini-btn" onclick="toggleMiniHudLayout()" title="컴팩트 2단 박스형과 슬림 1줄 가로 바형 레이아웃을 즉시 전환합니다">📐 가로바 전환</button>
        <button class="mini-btn" onclick="openUiSettingsFromMiniHud()" title="표시할 하드웨어 항목 선택 및 박스형/가로바 레이아웃 설정 화면 열기">⚙️ 설정</button>
        <button class="mini-btn active" onclick="exitMiniHudMode()" title="원래 창 크기와 위치로 즉시 복귀합니다 (Esc / F10)">⤢ 복귀</button>
      </div>
    </div>

    <div class="mini-hud-grid" id="mini-hud-grid" ondblclick="event.stopPropagation()">
      <!-- 1. 게임 FPS -->
      <div class="mini-hud-tile" id="mh-tile-fps">
        <div class="mini-hud-label">
          <span>🎮 FPS</span>
          <span id="mh-fps-low" style="color:var(--text-muted)">1%L 0</span>
        </div>
        <div class="mini-hud-val" id="mh-fps-val" style="color:var(--neon-green);">0 FPS</div>
        <div class="progress-track" style="height:4px;">
          <div class="progress-fill" id="mh-fps-bar" style="width:0%; background:var(--neon-green);"></div>
        </div>
        <div class="mini-hud-sub" id="mh-fps-sub">대기 중</div>
      </div>

      <!-- 2. CPU 부하 -->
      <div class="mini-hud-tile" id="mh-tile-cpu">
        <div class="mini-hud-label">
          <span>⚡ CPU</span>
          <span id="mh-cpu-core">0코어</span>
        </div>
        <div class="mini-hud-val" id="mh-cpu-val" style="color:var(--brand);">0.0%</div>
        <div class="progress-track" style="height:4px;">
          <div class="progress-fill" id="mh-cpu-bar" style="width:0%; background:var(--brand);"></div>
        </div>
        <div class="mini-hud-sub" id="mh-cpu-sub">최고 코어 0%</div>
      </div>

      <!-- 3. GPU & 온도 -->
      <div class="mini-hud-tile" id="mh-tile-gpu">
        <div class="mini-hud-label">
          <span>🎛️ GPU</span>
          <span id="mh-gpu-temp" style="color:var(--neon-green); font-weight:900;">0°C</span>
        </div>
        <div class="mini-hud-val" id="mh-gpu-val" style="color:var(--orange);">0.0%</div>
        <div class="progress-track" style="height:4px;">
          <div class="progress-fill" id="mh-gpu-bar" style="width:0%; background:var(--orange);"></div>
        </div>
        <div class="mini-hud-sub" id="mh-gpu-sub">VRAM 0.0 GB • 0W</div>
      </div>

      <!-- 4. 시스템 RAM -->
      <div class="mini-hud-tile" id="mh-tile-ram">
        <div class="mini-hud-label">
          <span>💾 RAM</span>
          <span id="mh-ram-swap">Swap 0G</span>
        </div>
        <div class="mini-hud-val" id="mh-ram-val" style="color:var(--purple);">0.0%</div>
        <div class="progress-track" style="height:4px;">
          <div class="progress-fill" id="mh-ram-bar" style="width:0%; background:var(--purple);"></div>
        </div>
        <div class="mini-hud-sub" id="mh-ram-sub">0.0 / 0.0 GB</div>
      </div>

      <!-- 5. 네트워크 속도 & 핑 -->
      <div class="mini-hud-tile" id="mh-tile-net">
        <div class="mini-hud-label">
          <span id="mh-net-label">🌐 NET/PING</span>
          <span id="mh-disk-io">💽 0.0M</span>
        </div>
        <div class="mini-hud-val" id="mh-net-val" style="color:var(--cyan);">0.0 ms</div>
        <div class="mini-hud-sub" id="mh-net-down">↓ 0.00 MB/s</div>
        <div class="mini-hud-sub" id="mh-net-up">↑ 0.00 MB/s</div>
      </div>

      <!-- 6. 플레이 시간 / 뽀모도로 타이머 -->
      <div class="mini-hud-tile" id="mh-tile-timer" onclick="togglePomodoro()" style="cursor:pointer;" title="클릭하여 뽀모도로 타이머 시작/일시정지">
        <div class="mini-hud-label">
          <span id="mh-timer-label">🍅 뽀모도로</span>
          <span id="mh-timer-state" style="color:var(--brand);">클릭제어</span>
        </div>
        <div class="mini-hud-val" id="mh-timer-val" style="color:var(--text-normal);">25:00</div>
        <div class="progress-track" style="height:4px;">
          <div class="progress-fill" id="mh-timer-bar" style="width:0%; background:var(--brand);"></div>
        </div>
        <div class="mini-hud-sub" id="mh-timer-sub">게임 시 플레이타임 표시</div>
      </div>
    </div>
  </div>

  <!-- 원하는 하드웨어 모니터링 선택 & 미니 HUD(박스형/가로바) 맞춤 설정 오버레이 -->
  <div id="uisettings-overlay" class="detail-overlay hidden">
    <div class="detail-header">
      <div class="detail-title-group">
        <div class="detail-title">🎛️ 하드웨어 모니터링 항목 선택 & 미니 HUD 맞춤 설정</div>
        <div class="detail-sub">내가 보고 싶은 하드웨어 지표만 골라서 띄우고, 미니 HUD를 '박스형'으로 쓸지 '가로바'로 쓸지 취향대로 설정하세요</div>
      </div>
      <div class="detail-actions">
        <button class="btn secondary" onclick="resetUiPrefs()">🔄 전체 기본값 복원</button>
        <button class="btn secondary" style="border-color:var(--neon-green); color:var(--neon-green);" onclick="closeUiSettingsModal(); enterMiniHudMode();">🗗 설정한 미니 HUD 바로 켜기 (F10)</button>
        <button class="btn" onclick="closeUiSettingsModal()">↙ 대시보드로 돌아가기 (Esc)</button>
      </div>
    </div>

    <div class="detail-body" style="gap: 16px;">
      <!-- 상단 원클릭 추천 프리셋 배너 -->
      <div class="card" style="flex-shrink: 0; overflow: visible; padding: 14px 18px; border-left: 4px solid var(--brand); background: rgba(var(--brand-rgb), 0.07);">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;">
          <div>
            <div style="font-size: 13.5px; font-weight: 800; color: var(--text-normal);">⚡ 원클릭 추천 구성 프리셋</div>
            <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">자주 쓰는 조합을 버튼 하나로 바로 적용한 뒤 아래에서 세부 항목을 자유롭게 켜고 끌 수 있습니다</div>
          </div>
          <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            <button class="btn secondary" onclick="applyUiPreset('all')">🌟 전체 다 보기 (기본)</button>
            <button class="btn secondary" onclick="applyUiPreset('gamer')">🎮 게이머 핵심 (FPS+GPU+CPU)</button>
            <button class="btn secondary" onclick="applyUiPreset('minimal')">🔥 초경량 (FPS+GPU 온도만)</button>
            <button class="btn secondary" onclick="applyUiPreset('work')">💻 작업/업무 집중 (CPU+RAM+할일)</button>
          </div>
        </div>
      </div>

      <!-- 메인 2열 설정 영역 -->
      <div style="display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.05fr); gap: 16px; flex-shrink: 0; padding-bottom: 12px;">

        <!-- 좌측: 통합 대시보드 하드웨어 모니터링 표시 항목 선택 -->
        <div class="card" style="overflow: visible; padding: 18px; gap: 14px;">
          <div class="card-header" style="margin-bottom: 0;">
            <div>
              <div class="card-title" style="font-size: 15px; color: var(--text-normal);">🖥️ 1. 메인 대시보드 모니터링 항목 선택</div>
              <div style="font-size: 12px; color: var(--text-muted); margin-top: 3px;">체크를 해제한 카드는 대시보드에서 숨겨지며, 남은 카드들이 빈자리 없이 화면에 맞춰 큼직하게 자동 정렬됩니다.</div>
            </div>
            <span class="badge" id="ui-dash-count-badge" style="color: var(--brand); flex-shrink: 0;">7 / 7개 표시 중</span>
          </div>

          <div style="font-size: 12px; font-weight: 800; color: var(--text-muted); margin-top: 2px;">상단 핵심 하드웨어 & 게이밍 카드 (4종)</div>
          <div class="custom-toggle-grid">
            <div class="custom-toggle-card active" id="uicard-dashCpu" onclick="toggleUiPref('dashCpu')">
              <div>
                <div style="font-size: 13px; font-weight: 800; color: var(--text-normal);">⚡ CPU 부하</div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">전체 사용률 및 논리 코어 상태</div>
              </div>
              <span class="switch-pill on" id="uipill-dashCpu">ON</span>
            </div>

            <div class="custom-toggle-card active" id="uicard-dashRam" onclick="toggleUiPref('dashRam')">
              <div>
                <div style="font-size: 13px; font-weight: 800; color: var(--text-normal);">💾 시스템 RAM</div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">물리 메모리 및 가상 메모리(Swap)</div>
              </div>
              <span class="switch-pill on" id="uipill-dashRam">ON</span>
            </div>

            <div class="custom-toggle-card active" id="uicard-dashGpu" onclick="toggleUiPref('dashGpu')">
              <div>
                <div style="font-size: 13px; font-weight: 800; color: var(--text-normal);">🎛️ GPU & VRAM</div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">그래픽카드 부하·온도·전력·VRAM</div>
              </div>
              <span class="switch-pill on" id="uipill-dashGpu">ON</span>
            </div>

            <div class="custom-toggle-card active" id="uicard-dashFps" onclick="toggleUiPref('dashFps')">
              <div>
                <div style="font-size: 13px; font-weight: 800; color: var(--text-normal);">🎮 게임 실시간 FPS</div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">인게임 프레임·1% Low·프레임타임</div>
              </div>
              <span class="switch-pill on" id="uipill-dashFps">ON</span>
            </div>
          </div>

          <div style="font-size: 12px; font-weight: 800; color: var(--text-muted); margin-top: 4px;">중단 요약 바 & 하단 상세 패널 (3종)</div>
          <div style="display: flex; flex-direction: column; gap: 9px;">
            <div class="custom-toggle-card active" id="uicard-dashNetDisk" onclick="toggleUiPref('dashNetDisk')">
              <div>
                <div style="font-size: 13px; font-weight: 800; color: var(--text-normal);">🌐 네트워크 속도·핑(Ping) & 디스크 I/O 요약 바</div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">실시간 다운로드/업로드 속도, 게임 서버 핑, 디스크 읽기/쓰기 한 줄 요약</div>
              </div>
              <span class="switch-pill on" id="uipill-dashNetDisk">ON</span>
            </div>

            <div class="custom-toggle-card active" id="uicard-dashProcs" onclick="toggleUiPref('dashProcs')">
              <div>
                <div style="font-size: 13px; font-weight: 800; color: var(--text-normal);">📊 실시간 상위 프로세스 목록 표</div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">CPU·메모리를 많이 쓰는 프로그램 확인 및 우클릭 강제 종료</div>
              </div>
              <span class="switch-pill on" id="uipill-dashProcs">ON</span>
            </div>

            <div class="custom-toggle-card active" id="uicard-dashPomo" onclick="toggleUiPref('dashPomo')">
              <div>
                <div style="font-size: 13px; font-weight: 800; color: var(--text-normal);">🍅 뽀모도로 집중 타이머 & 오늘 할 일 보드</div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">25분 집중 타이머와 체크리스트 (끄면 프로세스 표가 전체 폭으로 넓어집니다)</div>
              </div>
              <span class="switch-pill on" id="uipill-dashPomo">ON</span>
            </div>
          </div>
        </div>

        <!-- 우측: 미니 HUD 형태(박스형 vs 가로바) 및 표시 타일 설정 -->
        <div class="card" style="overflow: visible; padding: 18px; gap: 14px;">
          <div class="card-header" style="margin-bottom: 0;">
            <div>
              <div class="card-title" style="font-size: 15px; color: var(--text-normal);">🗗 2. 미니 HUD 스타일 (박스형 vs 가로바) & 항목 설정</div>
              <div style="font-size: 12px; color: var(--text-muted); margin-top: 3px;">단축키 <code>F10</code> 또는 상단 [🗗 미니 HUD] 버튼 클릭 시 전환되는 미니 상태창의 모양을 설정합니다.</div>
            </div>
            <span class="badge" id="ui-hud-count-badge" style="color: var(--neon-green); flex-shrink: 0;">6개 타일 활성</span>
          </div>

          <div style="font-size: 12px; font-weight: 800; color: var(--text-muted);">미니 HUD 창 모양 선택 (박스형 / 가로바형)</div>
          <div class="hud-style-grid">
            <!-- 박스형 선택 카드 -->
            <div class="hud-style-card selected" id="hudstyle-box" onclick="setMiniHudStylePref(false)">
              <div style="display: flex; align-items: center; justify-content: space-between;">
                <span style="font-size: 13.5px; font-weight: 800; color: var(--text-normal);">📦 컴팩트 박스형</span>
                <span class="badge" id="hudstyle-box-badge" style="background: var(--brand); color: #fff;">선택됨 ✓</span>
              </div>
              <div class="hud-diagram-box">
                <div class="hud-diagram-cell"></div>
                <div class="hud-diagram-cell"></div>
                <div class="hud-diagram-cell"></div>
                <div class="hud-diagram-cell"></div>
                <div class="hud-diagram-cell"></div>
                <div class="hud-diagram-cell"></div>
              </div>
              <div style="font-size: 11.5px; color: var(--text-muted); line-height: 1.45;">
                <strong>2단 바둑판 박스 모양</strong>으로 보조 모니터 구석이나 바탕화면 한쪽에 아담하게 모아 보기 좋습니다.
              </div>
            </div>

            <!-- 가로바 선택 카드 -->
            <div class="hud-style-card" id="hudstyle-bar" onclick="setMiniHudStylePref(true)">
              <div style="display: flex; align-items: center; justify-content: space-between;">
                <span style="font-size: 13.5px; font-weight: 800; color: var(--text-normal);">📏 슬림 가로 바형</span>
                <span class="badge" id="hudstyle-bar-badge">클릭하여 선택</span>
              </div>
              <div style="display: flex; align-items: center; flex: 1;">
                <div class="hud-diagram-bar" style="width: 100%;">
                  <div class="hud-diagram-cell"></div>
                  <div class="hud-diagram-cell"></div>
                  <div class="hud-diagram-cell"></div>
                  <div class="hud-diagram-cell"></div>
                  <div class="hud-diagram-cell"></div>
                  <div class="hud-diagram-cell"></div>
                </div>
              </div>
              <div style="font-size: 11.5px; color: var(--text-muted); line-height: 1.45;">
                <strong>1줄 슬림 가로 스트립 모양</strong>으로 모니터 상단·하단이나 창모드 게임 위쪽에 얇고 길게 띄워두기 좋습니다.
              </div>
            </div>
          </div>

          <!-- 미니 HUD 항상 위 고정 옵션 -->
          <div class="custom-toggle-card active" id="uicard-hudTopmost" onclick="toggleUiPref('hudTopmost')">
            <div>
              <div style="font-size: 13px; font-weight: 800; color: var(--text-normal);">📌 미니 HUD를 항상 다른 창 위에 고정 (Always on Top)</div>
              <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">게임이나 인터넷 창을 클릭해도 미니 HUD가 뒤로 가려지지 않고 항상 맨 위에 보이도록 고정합니다</div>
            </div>
            <span class="switch-pill on" id="uipill-hudTopmost">ON</span>
          </div>

          <!-- 미니 HUD에 표시할 타일 개별 선택 -->
          <div style="font-size: 12px; font-weight: 800; color: var(--text-muted); margin-top: 2px;">미니 HUD에 표시할 하드웨어 타일 선택 (원하는 항목만 골라 담기)</div>
          <div class="custom-toggle-grid" style="grid-template-columns: repeat(3, minmax(0, 1fr));">
            <div class="custom-toggle-card active" id="uicard-hudFps" onclick="toggleUiPref('hudFps')">
              <span style="font-size: 12.5px; font-weight: 800;">🎮 게임 FPS</span>
              <span class="switch-pill on" id="uipill-hudFps">ON</span>
            </div>
            <div class="custom-toggle-card active" id="uicard-hudCpu" onclick="toggleUiPref('hudCpu')">
              <span style="font-size: 12.5px; font-weight: 800;">⚡ CPU 부하</span>
              <span class="switch-pill on" id="uipill-hudCpu">ON</span>
            </div>
            <div class="custom-toggle-card active" id="uicard-hudGpu" onclick="toggleUiPref('hudGpu')">
              <span style="font-size: 12.5px; font-weight: 800;">🎛️ GPU·온도</span>
              <span class="switch-pill on" id="uipill-hudGpu">ON</span>
            </div>
            <div class="custom-toggle-card active" id="uicard-hudRam" onclick="toggleUiPref('hudRam')">
              <span style="font-size: 12.5px; font-weight: 800;">💾 시스템 RAM</span>
              <span class="switch-pill on" id="uipill-hudRam">ON</span>
            </div>
            <div class="custom-toggle-card active" id="uicard-hudNet" onclick="toggleUiPref('hudNet')">
              <span style="font-size: 12.5px; font-weight: 800;">🌐 핑·네트워크</span>
              <span class="switch-pill on" id="uipill-hudNet">ON</span>
            </div>
            <div class="custom-toggle-card active" id="uicard-hudTimer" onclick="toggleUiPref('hudTimer')">
              <span style="font-size: 12.5px; font-weight: 800;">⏱️ 플레이타임</span>
              <span class="switch-pill on" id="uipill-hudTimer">ON</span>
            </div>
          </div>

          <!-- 실시간 미니 HUD 배치 미리보기 -->
          <div style="background: var(--bg-primary); border: 1px dashed var(--border-subtle); border-radius: 10px; padding: 10px 12px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
              <span style="font-size: 11.5px; font-weight: 800; color: var(--text-muted);">👀 현재 설정된 미니 HUD 배치 미리보기</span>
              <span id="ui-hud-preview-meta" style="font-size: 11px; color: var(--brand); font-weight: 700;">📦 컴팩트 박스형 (3열 × 2단)</span>
            </div>
            <div id="ui-hud-live-preview" style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px;"></div>
          </div>
        </div>

      </div>
    </div>
  </div>

  <!-- 실행 중인 게임 프로세스 자동 탐색 & 관리 오버레이 -->
  <div id="gamescan-overlay" class="detail-overlay hidden">
    <div class="detail-header">
      <div class="detail-title-group">
        <div class="detail-title">🎮 실행 중인 게임 프로세스 탐지 & 관리</div>
        <div class="detail-sub">포그라운드 활성 창 • Steam / Epic / Riot / 배틀넷 / 넥슨 등 설치 폴더 • 3D 그래픽 부하 프로세스 자동 스캔</div>
      </div>
      <div class="detail-actions">
        <button class="btn ghost" onclick="refreshGameScanData()">🔄 지금 다시 스캔</button>
        <button class="btn ghost" onclick="resetToAutoDetect()">🎯 게임 자동 감지로 복원</button>
        <button class="btn" onclick="closeGameScanModal()">↙ 대시보드로 돌아가기 (Esc)</button>
      </div>
    </div>
    <div class="detail-content" style="display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr); gap: 16px;">
      <!-- 좌측: 실시간 감지된 게임 후보 목록 -->
      <div class="card" style="padding: 16px; overflow-y: auto;">
        <div class="card-head" style="margin-bottom: 12px;">
          <span class="card-title">🔍 실시간 탐지된 게임 프로세스 후보</span>
          <span id="scan-candidate-count" class="badge">0개 감지</span>
        </div>
        <div id="scan-candidate-list" style="display: flex; flex-direction: column; gap: 8px;">
          <div class="empty-state-box">스캔 중...</div>
        </div>

        <div class="card-head" style="margin-top: 24px; margin-bottom: 8px;">
          <span class="card-title">📋 전체 프로세스 검색에서 게임 직접 추가</span>
        </div>
        <input type="text" id="scan-proc-search" class="search-input" placeholder="실행 중인 프로세스 이름 검색 (예: game.exe, javaw, ff14)..." oninput="renderScanAllProcesses()" style="width: 100%; margin-bottom: 10px;">
        <div id="scan-all-proc-list" style="max-height: 220px; overflow-y: auto; display: flex; flex-direction: column; gap: 6px;"></div>
      </div>

      <!-- 우측: 영구 등록된 사용자 커스텀 게임 목록 -->
      <div class="card" style="padding: 16px; overflow-y: auto;">
        <div class="card-head" style="margin-bottom: 12px;">
          <span class="card-title">⭐ 영구 등록된 게임 목록 (자동 감지 대상)</span>
          <span id="scan-custom-count" class="badge">0개 등록</span>
        </div>
        <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
          여기에 등록된 실행 파일은 게임이 켜지는 순간 CoreFlow가 최우선으로 감지하여 플레이 타임과 FPS를 즉시 기록합니다.
        </div>
        <div id="scan-custom-list" style="display: flex; flex-direction: column; gap: 8px;">
          <div class="empty-state-box">등록된 사용자 정의 게임이 없습니다.</div>
        </div>
      </div>
    </div>
  </div>

  <!-- GitHub 자동 업데이트 확인 & 원클릭 설치 모달 -->
  <div id="update-overlay" class="detail-overlay hidden">
    <div class="detail-header">
      <div class="detail-title-group">
        <div class="detail-title">🔄 CoreFlow 버전 정보 및 GitHub 자동 업데이트</div>
        <div class="detail-sub">공식 저장소 (github.com/neverloselkb/coreFlow) Releases 연동 자동 업데이트 시스템</div>
      </div>
      <div class="detail-actions">
        <button class="btn secondary" onclick="checkForUpdates(true)">🔍 다시 확인</button>
        <button class="btn secondary" onclick="openGithubPage('https://github.com/neverloselkb/coreFlow/releases')">🌐 GitHub Releases 열기</button>
        <button class="btn" onclick="closeUpdateModal()">↙ 대시보드로 돌아가기 (Esc)</button>
      </div>
    </div>
    <div class="detail-body" style="max-width: 780px; margin: 0 auto; width: 100%; gap: 16px;">
      <div class="card" style="padding: 20px;">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
          <div style="display: flex; align-items: center; gap: 14px;">
            <img src="/favicon.ico" style="width: 52px; height: 52px; border-radius: 12px;">
            <div>
              <div style="font-size: 18px; font-weight: 800; color: var(--text-normal); display: flex; align-items: center; gap: 8px;">
                <span>CoreFlow</span>
                <span class="badge" id="upd-current-badge">현재 v__COREFLOW_APP_VERSION__</span>
                <span class="badge" id="upd-latest-badge" style="color: var(--neon-green);">확인 중...</span>
              </div>
              <div id="upd-status-headline" style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">
                GitHub 저장소에서 최신 릴리스 정보를 확인하고 있습니다...
              </div>
            </div>
          </div>
          <div id="upd-action-area">
            <button id="btn-do-update" class="btn" style="padding: 10px 18px; font-size: 13.5px; font-weight: 800; display: none;" onclick="triggerSelfUpdate()">
              🚀 원클릭 자동 업데이트 및 재시작
            </button>
          </div>
        </div>
      </div>

      <div class="card" style="padding: 18px;">
        <div class="card-head" style="margin-bottom: 10px;">
          <span class="card-title">📋 릴리스 노트 (Release Notes)</span>
          <span class="badge" id="upd-tag-label">neverloselkb/coreFlow</span>
        </div>
        <div id="upd-release-notes" style="font-size: 13px; color: var(--text-normal); line-height: 1.6; white-space: pre-wrap; background: var(--bg-primary); padding: 14px; border-radius: 8px; border: 1px solid var(--border-subtle); max-height: 280px; overflow-y: auto;">
          릴리스 정보를 불러오는 중...
        </div>
      </div>

      <div class="card" style="padding: 16px; font-size: 12.5px; color: var(--text-muted); line-height: 1.6;">
        <div style="font-weight: 800; color: var(--text-normal); margin-bottom: 4px;">💡 개발자 배포 가이드 (새 버전 업데이트 배포 방법)</div>
        <div>1. 코드 수정 후 <code>Cargo.toml</code>의 <code>version</code>을 올리고(예: <code>1.1.0</code>) <code>CoreFlow</code>와 <code>CoreFlow_Setup</code>을 빌드합니다.</div>
        <div>2. GitHub 저장소(<strong>neverloselkb/coreFlow</strong>)의 <strong>[Releases] → [Draft a new release]</strong>에서 태그(예: <code>v1.1.0</code>)를 생성하고, 빌드된 <strong><code>CoreFlow_Setup.exe</code></strong> 파일을 첨부하여 게시(Publish)합니다.</div>
        <div>3. 기존 사용자들이 CoreFlow를 실행하면 자동으로 새 버전을 감지하여 데이터 손실 없이 원클릭으로 업데이트됩니다!</div>
      </div>
    </div>
  </div>

  <!-- 메뉴별 도움말 & 하드웨어/게이밍 이상 징후 진단 가이드 오버레이 -->
  <div id="help-overlay" class="detail-overlay hidden">
    <div class="detail-header">
      <div class="detail-title-group">
        <div class="detail-title">❓ 알기 쉬운 PC 상태 & 게임 렉 진단 가이드</div>
        <div class="detail-sub">컴퓨터를 잘 몰라도 괜찮아요! 각 숫자가 무엇을 뜻하는지, 언제 왜 렉이 걸리는지 쉽게 알려드립니다</div>
      </div>
      <div class="detail-actions">
        <span class="badge" style="color: var(--brand);">단축키: F1 (열기) / Esc (닫기)</span>
        <button class="btn" onclick="closeHelpModal()">↙ 대시보드로 돌아가기 (Esc)</button>
      </div>
    </div>

    <div class="detail-body" style="gap: 16px;">
      <!-- 상단 빠른 단축키 & 핵심 활용 팁 요약 배너 -->
      <div class="card" style="flex-shrink: 0; overflow: visible; padding: 14px 18px; border-left: 4px solid var(--brand); background: rgba(var(--brand-rgb), 0.08);">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;">
          <div style="font-size: 13.5px; font-weight: 800; color: var(--text-normal);">
            💡 CoreFlow 200% 활용 핵심 단축키 & 조작 팁
          </div>
          <div style="display: flex; gap: 8px; flex-wrap: wrap; font-size: 12px;">
            <span class="badge">🖱️ 상단 카드 <strong>더블클릭</strong>: 크게 자세히 보기</span>
            <span class="badge">🖱️ 프로그램 이름 <strong>우클릭</strong>: 강제 끄기 / 게임으로 등록</span>
            <span class="badge">⌨️ <strong>F10</strong>: 작은 미니 창(HUD) 모드</span>
            <span class="badge">🔢 <strong>차트형 ↔ 수치 그리드</strong>: 그래프와 숫자 표 전환</span>
          </div>
        </div>
      </div>

      <!-- 2열 가이드 그리드 -->
      <div style="display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; flex-shrink: 0; padding-bottom: 12px;">

        <!-- 1. CPU 가이드 (컴퓨터의 두뇌) -->
        <div class="card" style="overflow: visible; padding: 18px; gap: 10px;">
          <div class="card-header" style="margin-bottom: 2px;">
            <div class="card-title" style="font-size: 15px; color: var(--brand); white-space: normal;">⚡ 1. CPU 부하 — "컴퓨터의 두뇌와 일꾼들"</div>
            <span class="badge" style="flex-shrink: 0;">통합 대시보드 / CPU 상세</span>
          </div>
          <div style="font-size: 12.5px; color: var(--text-normal); line-height: 1.65; display: flex; flex-direction: column; gap: 8px;">
            <div style="background: rgba(229, 57, 53, 0.1); border-left: 3px solid var(--red); padding: 10px 12px; border-radius: 6px;">
              <strong style="color: var(--red);">🚨 이럴 때 주의: 전체 CPU는 30%밖에 안 되는데, 작은 칸(Core) 1~2개만 95~100%로 꽉 찰 때</strong><br>
              CPU 안에는 여러 명의 일꾼(코어)이 있습니다. 전체 평균은 한가해 보여도, <strong>게임을 담당하는 대표 일꾼 1~2명이 과로로 지쳐 쓰러지기 직전</strong>인 상태입니다! 이러면 그래픽카드가 아무리 좋아도 게임 화면이 뚝뚝 끊깁니다.<br>
              <span style="color: var(--text-muted);">👉 <strong>해결 방법:</strong> 게임할 때는 뒤에 켜둔 인터넷 창(유튜브 등)이나 안 쓰는 메신저·런처를 꺼서 일꾼의 부담을 덜어주세요.</span>
            </div>
            <div style="background: rgba(245, 159, 0, 0.1); border-left: 3px solid var(--orange); padding: 10px 12px; border-radius: 6px;">
              <strong style="color: var(--orange);">⚠️ 이럴 때 주의: 아무것도 안 하고 바탕화면만 띄워놨는데 CPU가 계속 15% 이상일 때</strong><br>
              보이지 않는 곳에서 백신 검사(<code>MsMpEng.exe</code>)나 자동 업데이트, 혹은 제대로 안 꺼진 프로그램이 컴퓨터 힘을 몰래 쓰고 있는 것입니다. 아래 <strong>[실행 중인 프로세스]</strong> 표에서 <strong>CPU</strong> 글자를 눌러 많이 쓰는 순서대로 정렬한 뒤, 필요 없는 프로그램을 <strong>마우스 우클릭 → 강제 종료</strong>해 보세요.
            </div>
          </div>
        </div>

        <!-- 2. GPU & VRAM 가이드 (게임 그래픽 담당) -->
        <div class="card" style="overflow: visible; padding: 18px; gap: 10px;">
          <div class="card-header" style="margin-bottom: 2px;">
            <div class="card-title" style="font-size: 15px; color: var(--orange); white-space: normal;">🎛️ 2. GPU & VRAM — "게임 화면을 그려주는 그래픽카드"</div>
            <span class="badge" style="flex-shrink: 0;">하드웨어 GPU 상세</span>
          </div>
          <div style="font-size: 12.5px; color: var(--text-normal); line-height: 1.65; display: flex; flex-direction: column; gap: 8px;">
            <div style="background: rgba(229, 57, 53, 0.1); border-left: 3px solid var(--red); padding: 10px 12px; border-radius: 6px;">
              <strong style="color: var(--red);">🚨 이럴 때 주의: GPU 온도가 83°C~85°C를 넘으면서 갑자기 게임이 심하게 버벅거릴 때</strong><br>
              그래픽카드가 너무 뜨거워져서 <strong>"이러다 고장 나겠다!" 하고 스스로 속도를 확 줄여버리는 현상</strong>(과열 보호)입니다. 처음엔 잘 되던 게임이 20~30분 뒤부터 갑자기 끊긴다면 99% 이 온도 문제입니다.<br>
              <span style="color: var(--text-muted);">👉 <strong>해결 방법:</strong> [🔔 스마트 알림]에서 GPU 온도 경고를 80°C로 켜두시고, 본체 주변이 막혀 있지 않은지·먼지가 쌓이지 않았는지 확인해 주세요.</span>
            </div>
            <div style="background: rgba(245, 159, 0, 0.1); border-left: 3px solid var(--orange); padding: 10px 12px; border-radius: 6px;">
              <strong style="color: var(--orange);">⚠️ 이럴 때 주의: VRAM(비디오 메모리)이 90~95% 이상 꽉 찼을 때</strong><br>
              <strong>VRAM</strong>은 게임 속 배경·캐릭터 그림을 담아두는 '그래픽카드 전용 창고'입니다. 이 창고가 꽉 차면 마우스로 시야를 돌릴 때마다 화면이 0.5초씩 덜컥거리며 멈춥니다.<br>
              <span style="color: var(--text-muted);">👉 <strong>해결 방법:</strong> 게임 내 그래픽 설정에서 <strong>'텍스처(Texture) 품질'</strong>이나 '그림자' 옵션을 한 단계만 낮추면 거짓말처럼 부드러워집니다!</span>
            </div>
          </div>
        </div>

        <!-- 3. 시스템 RAM & 가상 메모리(Swap) 가이드 (컴퓨터의 작업 책상) -->
        <div class="card" style="overflow: visible; padding: 18px; gap: 10px;">
          <div class="card-header" style="margin-bottom: 2px;">
            <div class="card-title" style="font-size: 15px; color: var(--purple); white-space: normal;">💾 3. 시스템 RAM & Swap — "프로그램을 펼쳐놓는 작업 책상"</div>
            <span class="badge" style="flex-shrink: 0;">통합 대시보드 / RAM 상세</span>
          </div>
          <div style="font-size: 12.5px; color: var(--text-normal); line-height: 1.65; display: flex; flex-direction: column; gap: 8px;">
            <div style="background: rgba(229, 57, 53, 0.1); border-left: 3px solid var(--red); padding: 10px 12px; border-radius: 6px;">
              <strong style="color: var(--red);">🚨 이럴 때 주의: RAM이 85~90%를 넘고, Swap(가상 메모리) 숫자가 크게 올라갈 때</strong><br>
              <strong>RAM</strong>은 책상 넓이와 같습니다. 책상이 꽉 차면 컴퓨터는 어쩔 수 없이 느린 서랍장(저장장치 SSD/하드디스크, 즉 <strong>Swap</strong>)에 물건을 넣었다 뺐다 하기 시작합니다. 이때 화면 전환(알트+탭)이 엄청나게 느려지거나 게임이 갑자기 튕기게 됩니다.<br>
              <span style="color: var(--text-muted);">👉 <strong>해결 방법:</strong> 인터넷 브라우저(크롬, 엣지 등)는 창을 여러 개 켜두면 RAM을 엄청나게 차지합니다. 고사양 게임을 할 땐 인터넷 창을 꼭 닫아주세요.</span>
            </div>
            <div style="background: rgba(0, 200, 117, 0.08); border-left: 3px solid var(--neon-green); padding: 10px 12px; border-radius: 6px;">
              <strong style="color: var(--neon-green);">💡 알아두면 좋은 팁: 같은 게임을 3~4시간 연속으로 했더니 점점 느려진다면?</strong><br>
              오래 켜둔 게임이 다 쓴 책상 자리를 안 치워서 RAM이 점점 차오르는 현상입니다. 이럴 땐 <strong>게임을 한 번 껐다가 다시 켜기만 해도</strong> 처음처럼 다시 빨라집니다.
            </div>
          </div>
        </div>

        <!-- 4. 게임 FPS & 1% Low 가이드 (화면의 부드러움) -->
        <div class="card" style="overflow: visible; padding: 18px; gap: 10px;">
          <div class="card-header" style="margin-bottom: 2px;">
            <div class="card-title" style="font-size: 15px; color: var(--neon-green); white-space: normal;">🎮 4. 게임 FPS & 1% Low — "화면이 얼마나 매끄럽게 움직일까?"</div>
            <span class="badge" style="flex-shrink: 0;">게임 플레이 기록 / FPS 상세</span>
          </div>
          <div style="font-size: 12.5px; color: var(--text-normal); line-height: 1.65; display: flex; flex-direction: column; gap: 8px;">
            <div style="background: rgba(229, 57, 53, 0.1); border-left: 3px solid var(--red); padding: 10px 12px; border-radius: 6px;">
              <strong style="color: var(--red);">🚨 이럴 때 주의: 평균 FPS는 120으로 높은데, '1% Low FPS'가 30~40으로 낮게 나올 때</strong><br>
              <strong>FPS(프레임)</strong>는 1초에 화면을 몇 장 그려주는지(60 이상이면 부드러움)를 뜻합니다. 그런데 평균 점수가 120점이어도 <strong>가장 버벅거렸던 최악의 순간(1% Low)</strong>이 30점이라면, 우리 눈은 그 순간적인 멈칫거림 때문에 <em>"왜 이렇게 잔렉이 심하지?"</em>라고 느끼게 됩니다!<br>
              <span style="color: var(--text-muted);">👉 <strong>해결 방법:</strong> 게임 설정에서 '최대 프레임 제한'을 무제한 대신 모니터 성능(예: 60 또는 144)에 맞춰 고정해 두면, 그래픽카드가 무리하지 않아 이 잔렉이 확 줄어듭니다.</span>
            </div>
            <div style="background: rgba(245, 159, 0, 0.1); border-left: 3px solid var(--orange); padding: 10px 12px; border-radius: 6px;">
              <strong style="color: var(--orange);">⚠️ 이럴 때 주의: 보조 모니터의 다른 창을 클릭했을 때 프레임이 30~60으로 내려간다면?</strong><br>
              CoreFlow는 <strong>NVIDIA GeForce, AMD Radeon, Intel Arc</strong> 등 제조사에 상관없이 모든 그래픽 카드를 완벽 지원하며, <strong>Windows 하드웨어 DXGI/D3D9 그래픽 출력 신호(PresentMon 표준)</strong>를 직접 정밀 측정합니다. 다른 모니터를 클릭했을 때 FPS가 내려간다면 게임 내 그래픽 옵션의 <strong>'백그라운드 최대 프레임 제한(비활성 창 FPS 제한)'</strong> 기능이 작동한 정상 현상입니다. 미등록 게임은 <strong>[🔍 게임 직접 찾기/관리]</strong>에서 <strong>[⭐ 영구 등록]</strong>해 두세요!
            </div>
          </div>
        </div>

        <!-- 5. 네트워크(핑/지터) & 디스크 I/O 가이드 (인터넷과 저장장치) -->
        <div class="card" style="overflow: visible; padding: 18px; gap: 10px;">
          <div class="card-header" style="margin-bottom: 2px;">
            <div class="card-title" style="font-size: 15px; color: var(--cyan); white-space: normal;">🌐 5. 인터넷 핑(Ping) · 지터 & 디스크 — "통신 렉과 로딩 렉 찾기"</div>
            <span class="badge" style="flex-shrink: 0;">네트워크·디스크 모니터</span>
          </div>
          <div style="font-size: 12.5px; color: var(--text-normal); line-height: 1.65; display: flex; flex-direction: column; gap: 8px;">
            <div style="background: rgba(229, 57, 53, 0.1); border-left: 3px solid var(--red); padding: 10px 12px; border-radius: 6px;">
              <strong style="color: var(--red);">🚨 이럴 때 주의: 핑(Ping) 숫자가 높거나, '지터(흔들림)'가 15ms 이상일 때</strong><br>
              <strong>핑(Ping)</strong>은 내 컴퓨터와 게임 서버가 신호를 주고받는 반응 속도입니다(낮을수록 좋음: 1~50ms 쾌적 / 150ms 이상 느림). 특히 <strong>지터(Jitter)</strong>가 높으면 신호 속도가 빨랐다 느렸다 널뛰기하는 상태라, 게임 캐릭터가 제자리걸음을 하거나 순간이동을 하게 됩니다.<br>
              <span style="color: var(--text-muted);">👉 <strong>해결 방법:</strong> 와이파이(무선) 대신 랜선(유선)을 꽂거나, 뒤에서 토렌트·스팀 다운로드가 돌아가고 있는지 확인하세요.</span>
            </div>
            <div style="background: rgba(245, 159, 0, 0.1); border-left: 3px solid var(--orange); padding: 10px 12px; border-radius: 6px;">
              <strong style="color: var(--orange);">⚠️ 이럴 때 주의: 게임 중 갑자기 멈출 때 '디스크 쓰기(W)'가 수십 MB/s로 치솟아 있다면?</strong><br>
              게임이 저장장치(SSD/하드)에서 다음 맵을 불러와야 하는데, 뒤에서 <strong>스팀 자동 업데이트나 윈도우 업데이트가 저장장치를 혼자 독차지하고 있는 상황</strong>입니다. <strong>[네트워크-디스크-모니터]</strong> 메뉴 하단 표에서 누가 디스크를 쓰고 있는지 바로 찾을 수 있습니다.
            </div>
          </div>
        </div>

        <!-- 6. 녹화 분석 리포트 & 미니 HUD 가이드 -->
        <div class="card" style="overflow: visible; padding: 18px; gap: 10px;">
          <div class="card-header" style="margin-bottom: 2px;">
            <div class="card-title" style="font-size: 15px; color: var(--text-normal); white-space: normal;">📊 6. 녹화 분석 & 미니 HUD — "게임 중 렉 걸린 범인 나중에 찾기"</div>
            <span class="badge" style="flex-shrink: 0;">녹화 분석 / 미니 HUD</span>
          </div>
          <div style="font-size: 12.5px; color: var(--text-normal); line-height: 1.65; display: flex; flex-direction: column; gap: 8px;">
            <div style="background: rgba(var(--brand-rgb), 0.1); border-left: 3px solid var(--brand); padding: 10px 12px; border-radius: 6px;">
              <strong style="color: var(--brand);">🔍 꿀팁 1: "아까 한타할 때 잠깐 끊겼는데 도대체 왜 그랬지?" (블랙박스 녹화 기능)</strong><br>
              게임에 집중할 때는 이 화면을 쳐다볼 수 없죠! 게임 시작 전에 상단 <strong>[🔴 녹화 시작]</strong> 버튼만 눌러두세요. 게임이 끝난 뒤 <strong>[📊 분석 리포트]</strong>를 열면, 자동차 블랙박스처럼 <strong>아까 렉이 걸렸던 바로 그 시간에 온도가 튀었는지, 어떤 프로그램이 범인이었는지</strong> 마우스만 올려서 한눈에 찾아낼 수 있습니다.
            </div>
            <div style="background: rgba(0, 200, 117, 0.08); border-left: 3px solid var(--neon-green); padding: 10px 12px; border-radius: 6px;">
              <strong style="color: var(--neon-green);">🗗 꿀팁 2: 화면 구석에 작게 띄워두는 '미니 HUD (단축키 F10)'</strong><br>
              창이 너무 커서 부담스러울 땐 키보드 <strong><code>F10</code></strong> 키를 눌러보세요! 다른 창에 가려지지 않는 <strong>작고 예쁜 미니 상태창</strong>으로 변신하며, 한번 더 <code>F10</code>을 누르면 원래 크기로 돌아옵니다.
            </div>
          </div>
        </div>

      </div>
    </div>
  </div>

  <!-- 통신 지연 / 오류 발생 시 안내 및 즉시 복구 오버레이 -->
  <div id="error-fallback-overlay" class="hidden" style="position: fixed; inset: 0; z-index: 99999; background: rgba(0, 0, 0, 0.72); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); display: flex; align-items: center; justify-content: center; padding: 20px; animation: fadeIn 0.2s ease;">
    <div style="background: var(--bg-card); border: 1.5px solid rgba(229, 57, 53, 0.45); box-shadow: 0 16px 40px rgba(0, 0, 0, 0.6), 0 0 0 1px rgba(255, 255, 255, 0.05); border-radius: 16px; max-width: 540px; width: 100%; overflow: hidden; display: flex; flex-direction: column;">
      
      <!-- 상단 헤더 -->
      <div style="background: linear-gradient(135deg, rgba(229, 57, 53, 0.18) 0%, rgba(245, 159, 0, 0.12) 100%); border-bottom: 1px solid var(--border-subtle); padding: 20px 24px; display: flex; align-items: center; gap: 14px;">
        <div style="width: 44px; height: 44px; border-radius: 12px; background: rgba(229, 57, 53, 0.2); border: 1px solid rgba(229, 57, 53, 0.4); display: flex; align-items: center; justify-content: center; font-size: 24px; flex-shrink: 0;">
          ⚠️
        </div>
        <div>
          <div style="font-size: 17px; font-weight: 800; color: var(--text-normal); letter-spacing: -0.3px;">
            모니터링 연결 지연 또는 오류 안내
          </div>
          <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">
            CoreFlow 시스템 백엔드 엔진과의 통신이 일시적으로 중단되었습니다
          </div>
        </div>
      </div>

      <!-- 본문 내용 -->
      <div style="padding: 22px 24px; display: flex; flex-direction: column; gap: 16px;">
        <div style="font-size: 13px; line-height: 1.6; color: var(--text-normal);">
          윈도우 절전 모드 복귀, 게임/프로그램 전체화면 전환 중 순간 부하, 또는 백그라운드 엔진의 일시적인 응답 지연으로 발생할 수 있습니다.
        </div>

        <!-- 오류 세부 내용 -->
        <div id="error-fallback-detail-box" style="background: var(--bg-secondary); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 10px 14px; font-size: 11.5px; color: var(--text-muted); font-family: Consolas, monospace; word-break: break-all; max-height: 70px; overflow-y: auto;">
          연결 상태: 응답 대기 시간 초과 (Connection Timeout)
        </div>

        <div style="background: rgba(var(--brand-rgb), 0.08); border-left: 3px solid var(--brand); padding: 10px 14px; border-radius: 6px; font-size: 12px; color: var(--text-normal); line-height: 1.5;">
          💡 <strong>원클릭 재시작</strong>을 누르면 기존 설정(기록/테마/미니 HUD)은 안전하게 유지된 채 CoreFlow 엔진이 깨끗하게 다시 시작됩니다.
        </div>
      </div>

      <!-- 하단 액션 버튼 영역 -->
      <div style="background: var(--bg-secondary); border-top: 1px solid var(--border-subtle); padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap;">
        <button class="btn secondary" onclick="openHelpFromError()" style="font-size: 12px; padding: 8px 13px;">
          ❓ 진단 가이드 보기
        </button>
        <div style="display: flex; gap: 8px;">
          <button id="btn-retry-conn" class="btn secondary" onclick="retryConnectionNow()" style="font-size: 12.5px; padding: 8px 14px;">
            ⚡ 다시 연결 시도
          </button>
          <button id="btn-restart-app" class="btn" onclick="restartCoreFlowApp()" style="font-size: 12.5px; padding: 8px 16px; background-color: var(--brand); font-weight: 700;">
            🔄 프로그램 즉시 재시작
          </button>
        </div>
      </div>

    </div>
  </div>

  <!-- 프로세스 우클릭 커스텀 컨텍스트 메뉴 -->
  <div id="ctx-menu" class="ctx-menu hidden">
    <div id="ctx-header" class="ctx-header">process.exe (PID: 0)</div>
    <button class="ctx-item danger" onclick="killContextProcess()">🛑 프로세스 강제 종료 (Kill)</button>
    <button class="ctx-item" onclick="targetContextProcess()">🎯 FPS 모니터링 대상으로 지정</button>
    <button class="ctx-item" onclick="registerContextAsCustomGame()">⭐ 이 프로세스를 게임으로 영구 등록 (자동 감지)</button>
    <button class="ctx-item" onclick="copyContextPid()">📋 PID 복사</button>
  </div>

  <!-- 하단 상태 토스트 알림 -->
  <div id="toast" class="toast hidden">알림</div>

<script>
  // 브라우저 기본 우클릭 팝업 메뉴 전역 차단
  window.addEventListener('contextmenu', e => {
    e.preventDefault();
  });

  window.addEventListener('click', () => {
    hideContextMenu();
  });

  window.addEventListener('keydown', e => {
    if (e.key === 'F1') {
      e.preventDefault();
      openHelpModal();
      return;
    }
    if (e.key === 'F10') {
      e.preventDefault();
      if (isMiniHudMode) exitMiniHudMode();
      else enterMiniHudMode();
      return;
    }
    if (e.key === 'Escape') {
      if (isMiniHudMode) {
        exitMiniHudMode();
        return;
      }
      hideContextMenu();
      hideErrorFallbackOverlay();
      closeDetailView();
      closeRecordAnalysis();
      closeAlertSettings();
      closeGameScanModal();
      closeUpdateModal();
      closeUiSettingsModal();
      closeHelpModal();
    }
  });

  const cpuHistory = new Array(60).fill(0);
  const memHistory = new Array(60).fill(0);
  const gpuHistory = new Array(60).fill(0);
  const gpuTempHistory = new Array(60).fill(0);
  const fpsHistory = new Array(60).fill(0);
  const frameMsHistory = new Array(60).fill(0);
  const netRxHistory = new Array(60).fill(0);
  const netTxHistory = new Array(60).fill(0);
  const pingHistory = new Array(60).fill(0);
  const diskIoHistory = new Array(60).fill(0);
  let peakNetRxMbs = 0;
  let peakNetTxMbs = 0;
  let latestProcesses = [];
  let lastStatsData = null;
  let activeDetailType = null;
  let selectedTargetProc = 'auto';
  let themeOverride = 'auto';
  const SESSION_TOKEN = '__COREFLOW_SESSION_TOKEN__';
  let lastWinTheme = { is_light: true, accent: '#0078d4', accent_rgb: '0, 120, 212' };
  let currentDashboardViewMode = localStorage.getItem('coreflow_view_mode') || 'chart';

  function toggleDashboardViewMode() {
    currentDashboardViewMode = (currentDashboardViewMode === 'chart') ? 'grid' : 'chart';
    localStorage.setItem('coreflow_view_mode', currentDashboardViewMode);
    applyDashboardViewMode();
    if (lastStatsData) {
      updateGridMetricsUI(lastStatsData);
    }
    showToast(currentDashboardViewMode === 'grid' ? '🔢 수치 그리드 화면 모드로 전환되었습니다.' : '📊 차트 그래프 화면 모드로 전환되었습니다.');
  }

  function applyDashboardViewMode() {
    const isGrid = (currentDashboardViewMode === 'grid');
    const secMetrics = document.getElementById('sec-metrics');
    const secStrip = document.getElementById('sec-netdisk-strip');
    const detailOverlay = document.getElementById('detail-overlay');
    const btnIcon = document.getElementById('btn-view-mode-icon');
    const btnText = document.getElementById('btn-view-mode-text');
    const btnMode = document.getElementById('btn-view-mode');
    const dtBtnIcon = document.getElementById('btn-detail-view-mode-icon');
    const dtBtnText = document.getElementById('btn-detail-view-mode-text');
    const dtBtnMode = document.getElementById('btn-detail-view-mode');

    if (secMetrics) secMetrics.classList.toggle('view-mode-grid', isGrid);
    if (secStrip) secStrip.classList.toggle('view-mode-grid', isGrid);
    if (detailOverlay) detailOverlay.classList.toggle('view-mode-grid', isGrid);

    // 대시보드 상단 툴바 버튼 상태 갱신
    if (btnIcon && btnText) {
      if (isGrid) {
        btnIcon.textContent = '🔢';
        btnText.textContent = '수치 그리드';
        if (btnMode) {
          btnMode.classList.remove('secondary');
          btnMode.style.borderColor = 'var(--brand)';
          btnMode.style.backgroundColor = 'rgba(var(--brand-rgb), 0.16)';
          btnMode.style.color = 'var(--text-normal)';
        }
      } else {
        btnIcon.textContent = '📊';
        btnText.textContent = '차트형';
        if (btnMode) {
          btnMode.classList.add('secondary');
          btnMode.style.borderColor = '';
          btnMode.style.backgroundColor = '';
          btnMode.style.color = '';
        }
      }
    }

    // 상세보기 헤더 버튼 상태 갱신
    if (dtBtnIcon && dtBtnText) {
      if (isGrid) {
        dtBtnIcon.textContent = '🔢';
        dtBtnText.textContent = '수치 그리드';
        if (dtBtnMode) {
          dtBtnMode.classList.remove('secondary');
          dtBtnMode.style.borderColor = 'var(--brand)';
          dtBtnMode.style.backgroundColor = 'rgba(var(--brand-rgb), 0.16)';
          dtBtnMode.style.color = 'var(--text-normal)';
        }
      } else {
        dtBtnIcon.textContent = '📊';
        dtBtnText.textContent = '차트형';
        if (dtBtnMode) {
          dtBtnMode.classList.add('secondary');
          dtBtnMode.style.borderColor = '';
          dtBtnMode.style.backgroundColor = '';
          dtBtnMode.style.color = '';
        }
      }
    }

    if (activeDetailType && detailOverlay && !detailOverlay.classList.contains('hidden')) {
      renderDetailView();
    }
  }

  function apiFetch(url, options = {}) {
    const headers = Object.assign({}, options.headers || {}, {
      'X-CoreFlow-Token': SESSION_TOKEN
    });
    return fetch(url, Object.assign({}, options, { headers }));
  }

  // 모니터링 녹화 및 정밀 분석 상태
  let isRecording = false;
  let recordStartTime = null;
  let recordEndTime = null;
  let recordedSamples = [];
  let lastSavedFilePath = '';
  let lastSavedFileName = '';
  let recSeriesVisible = { cpu: true, mem: true, gpu: true, temp: true, fps: true };
  let scrubHoverIndex = -1;

  // 프로세스 정렬 및 우클릭 타겟 상태
  let procSortKey = 'mem_mb';
  let procSortAsc = false;
  let ctxTargetPid = null;
  let ctxTargetName = '';
  let toastTimer = null;

  function showToast(msg) {
    const el = document.getElementById('toast');
    el.textContent = msg;
    el.classList.remove('hidden');
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      el.classList.add('hidden');
    }, 2600);
  }

  function procIconHtml(name, size = 16) {
    if (!name) return '';
    return `<img class="proc-icon" style="width:${size}px;height:${size}px;" src="/api/proc_icon?name=${encodeURIComponent(name)}" alt="" draggable="false">`;
  }

  function showProcContextMenu(e, pid, name) {
    e.preventDefault();
    e.stopPropagation();
    ctxTargetPid = pid;
    ctxTargetName = name;

    const menu = document.getElementById('ctx-menu');
    document.getElementById('ctx-header').innerHTML = `<span class="proc-name-cell">${procIconHtml(name, 15)}<span>${escapeHtml(name)} (PID: ${pid})</span></span>`;
    menu.classList.remove('hidden');

    const menuW = 220;
    const menuH = 135;
    const x = Math.min(window.innerWidth - menuW - 10, e.clientX);
    const y = Math.min(window.innerHeight - menuH - 10, e.clientY);
    menu.style.left = `${Math.max(8, x)}px`;
    menu.style.top = `${Math.max(8, y)}px`;
  }

  function hideContextMenu() {
    const menu = document.getElementById('ctx-menu');
    if (menu) menu.classList.add('hidden');
  }

  async function killContextProcess() {
    if (!ctxTargetPid) return;
    const pid = ctxTargetPid;
    const name = ctxTargetName;
    hideContextMenu();
    try {
      const res = await apiFetch(`/api/kill?pid=${pid}`, { method: 'POST' });
      const data = await res.json();
      if (data.ok) {
        showToast(`✅ ${name} (PID: ${pid}) 프로세스를 종료했습니다.`);
        fetchStats();
      } else {
        showToast(`⚠️ ${name} (PID: ${pid}) 종료 실패 (권한 또는 시스템 프로세스)`);
      }
    } catch (err) {
      showToast(`⚠️ 프로세스 종료 요청 중 오류가 발생했습니다.`);
    }
  }

  function targetContextProcess() {
    if (!ctxTargetName) return;
    selectedTargetProc = ctxTargetName;
    hideContextMenu();
    updateProcessDropdown();
    document.getElementById('game-select').value = ctxTargetName;
    showToast(`🎯 ${ctxTargetName} 프로세스를 FPS 모니터링 대상으로 지정했습니다.`);
    fetchStats();
  }

  async function registerContextAsCustomGame() {
    if (!ctxTargetName) return;
    const exe = ctxTargetName;
    hideContextMenu();
    const cleanName = exe.replace(/\.exe$/i, '').replace(/[-_]/g, ' ');
    const userTitle = prompt(`'${exe}' 프로세스를 게임으로 영구 등록합니다.\n표시할 게임 이름을 입력하세요:`, cleanName);
    if (!userTitle || !userTitle.trim()) return;
    try {
      const res = await apiFetch(`/api/custom_game?exe=${encodeURIComponent(exe)}&name=${encodeURIComponent(userTitle.trim())}`, { method: 'POST' });
      const data = await res.json();
      if (data.ok) {
        showToast(`⭐ '${userTitle.trim()}' (${exe}) 게임으로 영구 등록되었습니다! 이제 실행 시 자동 감지됩니다.`);
        fetchStats();
      } else {
        showToast(`⚠️ 게임 등록에 실패했습니다.`);
      }
    } catch (e) {
      showToast(`⚠️ 게임 등록 중 오류가 발생했습니다.`);
    }
  }

  // ==================== 실행 중인 게임 프로세스 정밀 탐지 & 관리 ====================
  let lastScanData = null;

  function openGameScanModal() {
    closeDetailView();
    closeRecordAnalysis();
    closeAlertSettings();
    closeUpdateModal();
    closeUiSettingsModal();
    closeHelpModal();
    const overlay = document.getElementById('gamescan-overlay');
    if (overlay) overlay.classList.remove('hidden');
    refreshGameScanData();
  }

  function closeGameScanModal() {
    const overlay = document.getElementById('gamescan-overlay');
    if (overlay && !overlay.classList.contains('hidden')) {
      overlay.classList.add('hidden');
    }
  }

  function resetToAutoDetect() {
    selectedTargetProc = 'auto';
    updateProcessDropdown();
    document.getElementById('game-select').value = 'auto';
    showToast('🎯 모니터링 대상이 [게임 자동 감지] 모드로 설정되었습니다.');
    fetchStats();
    refreshGameScanData();
  }

  async function refreshGameScanData() {
    const candListEl = document.getElementById('scan-candidate-list');
    if (candListEl) candListEl.innerHTML = '<div class="empty-state-box">⚡ 실행 중인 모든 프로세스를 정밀 스캔하고 있습니다...</div>';
    try {
      const res = await apiFetch('/api/game_scan');
      const data = await res.json();
      if (!data.ok) return;
      lastScanData = data;
      renderScanCandidates(data.candidates || [], data.active_game || {});
      renderScanCustomGames(data.custom_games || []);
      renderScanAllProcesses();
    } catch (e) {
      if (candListEl) candListEl.innerHTML = '<div class="empty-state-box">⚠️ 프로세스 스캔에 실패했습니다.</div>';
    }
  }

  function renderScanCandidates(candidates, activeGame) {
    const candListEl = document.getElementById('scan-candidate-list');
    const countBadge = document.getElementById('scan-candidate-count');
    if (countBadge) countBadge.textContent = `${candidates.length}개 감지`;
    if (!candListEl) return;

    if (candidates.length === 0) {
      candListEl.innerHTML = `
        <div class="empty-state-box">
          <div style="font-size:24px;">🎮</div>
          <div style="font-weight:700;">현재 명확히 감지된 게임 프로세스가 없습니다.</div>
          <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">
            게임을 실행 중인 경우 포그라운드로 한번 활성화(클릭)하시거나, 아래 <strong>[전체 프로세스 검색]</strong>에서 실행 중인 게임을 직접 찾아 <strong>[⭐ 게임으로 등록]</strong>해 보세요!
          </div>
        </div>
      `;
      return;
    }

    candListEl.innerHTML = candidates.map(c => {
      const isTarget = selectedTargetProc === c.name || (selectedTargetProc === 'auto' && activeGame.pid === c.pid);
      const fgBadge = c.is_foreground ? '<span class="badge" style="color:var(--neon-green)">🟢 현재 활성 창</span>' : '';
      const customBadge = c.is_custom ? '<span class="badge" style="color:#f59f00">⭐ 사용자 등록</span>' : '';
      const activeBadge = isTarget ? '<span class="badge" style="color:var(--brand)">🎯 모니터링 중</span>' : '';
      return `
        <div class="rank-item" style="padding:10px 14px; background:var(--bg-card); border-radius:8px; border:1px solid ${isTarget ? 'var(--brand)' : 'var(--border-subtle)'};">
          <div class="rank-top-row" style="margin-bottom:4px;">
            <div class="rank-name-wrap">
              ${procIconHtml(c.name, 20)}
              <strong style="font-size:14px; color:var(--text-normal);">${escapeHtml(c.title)}</strong>
              <small style="color:var(--text-muted); font-family:monospace;">(${escapeHtml(c.name)} • PID: ${c.pid})</small>
              ${activeBadge}
              ${fgBadge}
              ${customBadge}
            </div>
            <div style="display:flex; gap:6px;">
              <button class="btn" style="padding:4px 10px; font-size:12px;" onclick="selectGameCandidate('${escapeJsStr(c.name)}')">🎯 이 게임 모니터링</button>
              ${!c.is_custom ? `<button class="btn secondary" style="padding:4px 10px; font-size:12px;" onclick="registerCustomGameDirect('${escapeJsStr(c.name)}', '${escapeJsStr(c.title)}')">⭐ 영구 등록</button>` : ''}
            </div>
          </div>
          <div style="display:flex; justify-content:space-between; align-items:center; font-size:12px; color:var(--text-muted);">
            <span>💡 <strong>탐지 근거:</strong> ${escapeHtml(c.reason)}</span>
            <span style="font-variant-numeric:tabular-nums;">CPU <strong>${c.cpu.toFixed(1)}%</strong> • RAM <strong>${c.mem_mb.toFixed(0)} MB</strong></span>
          </div>
        </div>
      `;
    }).join('');
  }

  function renderScanCustomGames(customGames) {
    const listEl = document.getElementById('scan-custom-list');
    const countBadge = document.getElementById('scan-custom-count');
    if (countBadge) countBadge.textContent = `${customGames.length}개 등록`;
    if (!listEl) return;

    if (customGames.length === 0) {
      listEl.innerHTML = `
        <div class="empty-state-box">
          등록된 사용자 정의 게임이 없습니다.<br>왼쪽 탐지 후보 또는 아래 프로세스 검색에서 원하는 실행 파일을 등록할 수 있습니다.
        </div>
      `;
      return;
    }

    listEl.innerHTML = customGames.map(cg => `
      <div class="rank-item" style="padding:8px 12px; background:var(--bg-card); border-radius:8px; border:1px solid var(--border-subtle); display:flex; justify-content:space-between; align-items:center;">
        <div style="display:flex; align-items:center; gap:8px;">
          ${procIconHtml(cg.exe, 18)}
          <div>
            <strong style="color:var(--text-normal); font-size:13.5px;">${escapeHtml(cg.name)}</strong>
            <div style="font-size:11.5px; color:var(--text-muted); font-family:monospace;">${escapeHtml(cg.exe)}</div>
          </div>
        </div>
        <div style="display:flex; gap:6px;">
          <button class="btn ghost" style="padding:3px 8px; font-size:11px;" onclick="selectGameCandidate('${escapeJsStr(cg.exe)}')">선택</button>
          <button class="btn ghost" style="padding:3px 8px; font-size:11px; color:var(--red);" onclick="deleteCustomGame('${escapeJsStr(cg.exe)}')">🗑️ 삭제</button>
        </div>
      </div>
    `).join('');
  }

  function renderScanAllProcesses() {
    const q = (document.getElementById('scan-proc-search')?.value || '').trim().toLowerCase();
    const container = document.getElementById('scan-all-proc-list');
    if (!container) return;
    if (!latestProcesses || latestProcesses.length === 0) {
      container.innerHTML = '<div style="color:var(--text-muted); font-size:12px; padding:8px;">실행 중인 프로세스 목록을 불러오는 중...</div>';
      return;
    }

    const filtered = latestProcesses
      .filter(p => !q || p.name.toLowerCase().includes(q) || String(p.pid).includes(q))
      .slice(0, 40);

    if (filtered.length === 0) {
      container.innerHTML = `<div style="color:var(--text-muted); font-size:12px; padding:8px;">'${escapeHtml(q)}' 검색어와 일치하는 프로세스가 없습니다.</div>`;
      return;
    }

    container.innerHTML = filtered.map(p => {
      const cleanName = p.name.replace(/\.exe$/i, '').replace(/[-_]/g, ' ');
      return `
        <div style="display:flex; justify-content:space-between; align-items:center; padding:5px 8px; background:rgba(255,255,255,0.03); border-radius:6px; font-size:12px;">
          <div class="proc-name-cell" style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:260px;">
            ${procIconHtml(p.name, 16)}
            <strong style="color:var(--text-normal);">${escapeHtml(p.name)}</strong>
            <span style="color:var(--text-muted); margin-left:4px;">(PID: ${p.pid} • ${p.mem_mb.toFixed(0)} MB)</span>
          </div>
          <div style="display:flex; gap:4px;">
            <button class="btn secondary" style="padding:2px 8px; font-size:11px;" onclick="selectGameCandidate('${escapeJsStr(p.name)}')">타겟 지정</button>
            <button class="btn ghost" style="padding:2px 8px; font-size:11px; color:#f59f00;" onclick="registerCustomGameDirect('${escapeJsStr(p.name)}', '${escapeJsStr(cleanName)}')">⭐ 게임 등록</button>
          </div>
        </div>
      `;
    }).join('');
  }

  function selectGameCandidate(exeName) {
    selectedTargetProc = exeName;
    updateProcessDropdown();
    document.getElementById('game-select').value = exeName;
    showToast(`🎯 '${exeName}' 프로세스를 모니터링 대상으로 지정했습니다.`);
    fetchStats();
    if (lastScanData) {
      renderScanCandidates(lastScanData.candidates || [], { exe: exeName });
    }
  }

  async function registerCustomGameDirect(exe, defaultTitle) {
    const userTitle = prompt(`'${exe}' 프로세스를 게임으로 영구 등록합니다.\n표시할 게임 이름을 입력하세요:`, defaultTitle || exe);
    if (!userTitle || !userTitle.trim()) return;
    try {
      const res = await apiFetch(`/api/custom_game?exe=${encodeURIComponent(exe)}&name=${encodeURIComponent(userTitle.trim())}`, { method: 'POST' });
      const data = await res.json();
      if (data.ok) {
        showToast(`⭐ '${userTitle.trim()}' (${exe}) 게임이 영구 등록되었습니다!`);
        fetchStats();
        refreshGameScanData();
      }
    } catch (e) {
      showToast('⚠️ 게임 등록 중 오류가 발생했습니다.');
    }
  }

  async function deleteCustomGame(exe) {
    if (!confirm(`'${exe}' 프로세스를 영구 등록 게임 목록에서 삭제하시겠습니까?`)) return;
    try {
      const res = await apiFetch(`/api/delete_custom_game?exe=${encodeURIComponent(exe)}`, { method: 'POST' });
      const data = await res.json();
      if (data.ok) {
        showToast(`🗑️ '${exe}' 등록이 해제되었습니다.`);
        fetchStats();
        refreshGameScanData();
      }
    } catch (e) {
      showToast('⚠️ 삭제 요청 중 오류가 발생했습니다.');
    }
  }

  function copyContextPid() {
    if (!ctxTargetPid) return;
    const pid = String(ctxTargetPid);
    hideContextMenu();
    if (navigator.clipboard) {
      navigator.clipboard.writeText(pid);
    }
    showToast(`📋 PID ${pid} 복사됨`);
  }

  function toggleSort(key) {
    if (procSortKey === key) {
      procSortAsc = !procSortAsc;
    } else {
      procSortKey = key;
      // 이름과 PID는 첫 클릭 시 오름차순, CPU와 메모리는 첫 클릭 시 내림차순
      procSortAsc = (key === 'name' || key === 'pid');
    }
    updateSortHeaders();
    renderProcesses();
  }

  function updateSortHeaders() {
    const labels = {
      pid: 'PID',
      name: '프로세스 이름',
      cpu: 'CPU',
      mem_mb: '메모리 (MB)'
    };
    ['pid', 'name', 'cpu', 'mem_mb'].forEach(k => {
      const th = document.getElementById('th-' + k);
      if (!th) return;
      if (k === procSortKey) {
        th.classList.add('active-sort');
        th.textContent = `${labels[k]} ${procSortAsc ? '▲' : '▼'}`;
      } else {
        th.classList.remove('active-sort');
        th.textContent = labels[k];
      }
    });
  }

  // 디스플레이 실시간 프레임 측정기
  let rafFrames = 0;
  let rafLastTime = performance.now();
  let compositorFps = 60;
  let compositorFrameMs = 16.67;

  function rafLoop(now) {
    rafFrames++;
    const elapsed = now - rafLastTime;
    if (elapsed >= 500) {
      compositorFps = Math.round((rafFrames * 1000) / elapsed);
      compositorFrameMs = elapsed / rafFrames;
      rafFrames = 0;
      rafLastTime = now;
    }
    requestAnimationFrame(rafLoop);
  }
  requestAnimationFrame(rafLoop);

  function getBrowserSystemAccent() {
    const probe = document.getElementById('win-accent-probe');
    if (!probe) return { hex: '#0078d4', rgb: '0, 120, 212' };
    const cs = getComputedStyle(probe).color;
    const m = cs.match(/(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/);
    if (m) {
      const r = parseInt(m[1], 10);
      const g = parseInt(m[2], 10);
      const b = parseInt(m[3], 10);
      const hex = '#' + [r, g, b].map(x => x.toString(16).padStart(2, '0')).join('');
      return { hex, rgb: `${r}, ${g}, ${b}` };
    }
    return { hex: '#0078d4', rgb: '0, 120, 212' };
  }

  function applyWindowsTheme(winTheme) {
    if (winTheme) lastWinTheme = winTheme;
    const isLight = themeOverride === 'auto'
      ? Boolean(lastWinTheme.is_light)
      : (themeOverride === 'light');

    document.body.classList.toggle('theme-light', isLight);

    const sysAccent = getBrowserSystemAccent();
    const accent = (lastWinTheme.accent && lastWinTheme.accent.length > 0) ? lastWinTheme.accent : sysAccent.hex;
    const accentRgb = (lastWinTheme.accent_rgb && lastWinTheme.accent_rgb.length > 0) ? lastWinTheme.accent_rgb : sysAccent.rgb;
    document.documentElement.style.setProperty('--brand', accent);
    document.documentElement.style.setProperty('--brand-rgb', accentRgb);

    const modeName = isLight ? '라이트' : '다크';
    document.getElementById('theme-status-text').textContent = `${modeName} • ${accent.toUpperCase()}`;
    return { accent, accentRgb };
  }

  function onChangeThemeOverride() {
    themeOverride = document.getElementById('theme-mode-select').value;
    applyWindowsTheme(lastWinTheme);
    fetch('/api/stats?' + getWindowBoundsQuery()).catch(() => {});
  }

  // 뽀모도로 상태
  let pomoIsBreak = false;
  let pomoTotal = 25 * 60;
  let pomoRemaining = 25 * 60;
  let pomoRunning = false;

  // 할 일 상태 (포트 변경과 무관하게 로컬 파일 coreflow_todos.json에 영구 저장)
  let todos = /*__COREFLOW_INITIAL_TODOS__*/[];

  function saveTodos() {
    apiFetch('/api/todos', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(todos)
    }).catch(() => {});
    renderTodos();
  }

  function renderTodos() {
    const list = document.getElementById('todo-list');
    list.innerHTML = '';
    let doneCount = 0;
    if (todos.length === 0) {
      list.innerHTML = `
        <div style="text-align: center; padding: 24px 12px; color: var(--text-muted); font-size: 12.5px;">
          등록된 할 일이 없습니다. 위 입력창에서 새로운 할 일을 추가해 보세요!
        </div>
      `;
      document.getElementById('todo-counter').textContent = `0 / 0 완료`;
      return;
    }
    todos.forEach((t, idx) => {
      if (t.done) doneCount++;
      const row = document.createElement('div');
      row.className = 'todo-item' + (t.done ? ' done' : '');
      row.onclick = () => {
        todos[idx].done = !todos[idx].done;
        saveTodos();
      };
      row.innerHTML = `
        <div class="todo-left">
          <div class="checkbox">${t.done ? '✔' : ''}</div>
          <span class="todo-text">${escapeHtml(t.text)}</span>
        </div>
        <button class="todo-del" onclick="event.stopPropagation(); deleteTodo(${idx})">삭제</button>
      `;
      list.appendChild(row);
    });
    document.getElementById('todo-counter').textContent = `${doneCount} / ${todos.length} 완료`;
  }

  function addTodo() {
    const input = document.getElementById('todo-input');
    const val = input.value.trim();
    if (!val) return;
    todos.push({ text: val, done: false });
    input.value = '';
    saveTodos();
  }

  function deleteTodo(idx) {
    todos.splice(idx, 1);
    saveTodos();
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
  }

  // 뽀모도로 타이머 제어
  function updatePomoUI() {
    const m = String(Math.floor(pomoRemaining / 60)).padStart(2, '0');
    const s = String(pomoRemaining % 60).padStart(2, '0');
    document.getElementById('pomo-time-display').textContent = `${m}:${s}`;
    const pct = pomoTotal > 0 ? ((pomoTotal - pomoRemaining) / pomoTotal) * 100 : 0;
    document.getElementById('pomo-bar').style.width = `${pct.toFixed(1)}%`;
    document.getElementById('pomo-start-btn').textContent = pomoRunning ? '일시정지' : '시작';
    document.getElementById('pomo-status-badge').textContent = pomoRunning ? '진행 중 🔥' : '일시정지';
    document.getElementById('pomo-mode-title').textContent = pomoIsBreak
      ? '☕ 휴식 타이머 (5분)'
      : '🍅 뽀모도로 집중 타이머 (25분)';
  }

  function togglePomodoro() {
    pomoRunning = !pomoRunning;
    updatePomoUI();
  }

  function resetPomodoro() {
    pomoRunning = false;
    pomoRemaining = pomoTotal;
    updatePomoUI();
  }

  function switchPomodoroMode() {
    pomoRunning = false;
    pomoIsBreak = !pomoIsBreak;
    pomoTotal = pomoIsBreak ? 5 * 60 : 25 * 60;
    pomoRemaining = pomoTotal;
    updatePomoUI();
  }

  setInterval(() => {
    if (pomoRunning) {
      if (pomoRemaining > 0) {
        pomoRemaining--;
      } else {
        switchPomodoroMode();
      }
      updatePomoUI();
    }
  }, 1000);

  // 탭 전환
  let activeMainTab = 'overview';
  let gameLogPeriod = '7d';
  let latestGameLogs = [];

  function formatHMS(totalSecs) {
    const s = Math.max(0, Math.floor(totalSecs || 0));
    const hrs = Math.floor(s / 3600);
    const mins = Math.floor((s % 3600) / 60);
    const secs = s % 60;
    return `${String(hrs).padStart(2, '0')}:${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
  }

  function formatDurationReadable(totalSecs) {
    const s = Math.max(0, Math.floor(totalSecs || 0));
    const hrs = Math.floor(s / 3600);
    const mins = Math.floor((s % 3600) / 60);
    const secs = s % 60;
    if (hrs > 0) return `${hrs}시간 ${mins}분 ${secs}초`;
    if (mins > 0) return `${mins}분 ${secs}초`;
    return `${secs}초`;
  }

  function formatSessionTimeRange(startTs, endTs, isActive) {
    if (!startTs) return '-';
    const d1 = new Date(startTs * 1000);
    const pad = n => String(n).padStart(2, '0');
    const datePart = `${d1.getFullYear()}-${pad(d1.getMonth() + 1)}-${pad(d1.getDate())}`;
    const startClock = `${pad(d1.getHours())}:${pad(d1.getMinutes())}:${pad(d1.getSeconds())}`;
    if (isActive) {
      return `${datePart} ${startClock} ~ 진행 중 🔴`;
    }
    const d2 = new Date((endTs || startTs) * 1000);
    const endClock = `${pad(d2.getHours())}:${pad(d2.getMinutes())}:${pad(d2.getSeconds())}`;
    return `${datePart} ${startClock} ~ ${endClock}`;
  }

  function switchTab(tab) {
    activeMainTab = tab;
    closeDetailView();
    closeRecordAnalysis();
    closeAlertSettings();
    closeUiSettingsModal();
    closeHelpModal();
    ['overview', 'system', 'netdisk', 'gamelog', 'productivity', 'analysis', 'alerts', 'uisettings', 'help'].forEach(t => {
      const ch = document.getElementById('chan-' + t);
      const rl = document.getElementById('rail-' + t);
      if (ch) ch.classList.toggle('active', t === tab);
      if (rl) rl.classList.toggle('active', t === tab);
    });

    const secMetrics = document.getElementById('sec-metrics');
    const secNetdiskStrip = document.getElementById('sec-netdisk-strip');
    const secCores = document.getElementById('sec-cores');
    const secBottom = document.getElementById('sec-bottom');
    const secGamelog = document.getElementById('sec-gamelog');
    const secNetdisk = document.getElementById('sec-netdisk');
    const cardProc = document.getElementById('card-processes');
    const cardProd = document.getElementById('card-productivity');

    if (tab === 'overview') {
      document.getElementById('top-title').textContent = '통합-대시보드';
      document.getElementById('top-desc').textContent = 'CPU • GPU • 네트워크/디스크 • 게임 FPS & 실행 시간 실시간 모니터';
      secMetrics.classList.remove('hidden');
      if (secNetdiskStrip) secNetdiskStrip.classList.remove('hidden');
      secCores.classList.add('hidden');
      secBottom.classList.remove('hidden');
      secGamelog.classList.add('hidden');
      if (secNetdisk) secNetdisk.classList.add('hidden');
      secBottom.style.gridTemplateColumns = 'minmax(0, 1.35fr) minmax(0, 1fr)';
      cardProc.classList.remove('hidden');
      cardProd.classList.remove('hidden');
      applyUiPrefs(false);
    } else if (tab === 'system') {
      document.getElementById('top-title').textContent = '하드웨어-GPU-상세';
      document.getElementById('top-desc').textContent = '논리 코어별 부하 • GPU 전력/클럭 • 전체 프로세스';
      secMetrics.classList.remove('hidden');
      secMetrics.style.gridTemplateColumns = '';
      ['card-metric-cpu', 'card-metric-mem', 'card-metric-gpu', 'card-metric-fps'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.remove('hidden');
      });
      if (secNetdiskStrip) secNetdiskStrip.classList.add('hidden');
      secCores.classList.remove('hidden');
      secBottom.classList.remove('hidden');
      secGamelog.classList.add('hidden');
      if (secNetdisk) secNetdisk.classList.add('hidden');
      secBottom.style.gridTemplateColumns = 'minmax(0, 1fr)';
      cardProc.classList.remove('hidden');
      cardProd.classList.add('hidden');
    } else if (tab === 'netdisk') {
      document.getElementById('top-title').textContent = '네트워크-디스크-모니터';
      document.getElementById('top-desc').textContent = '실시간 다운로드/업로드 속도 • 핑(Ping/Jitter) • 드라이브 용량 및 디스크 I/O';
      secMetrics.classList.add('hidden');
      if (secNetdiskStrip) secNetdiskStrip.classList.add('hidden');
      secCores.classList.add('hidden');
      secBottom.classList.add('hidden');
      secGamelog.classList.add('hidden');
      if (secNetdisk) secNetdisk.classList.remove('hidden');
      renderNetDiskDashboard();
    } else if (tab === 'gamelog') {
      document.getElementById('top-title').textContent = '게임-플레이-기록';
      document.getElementById('top-desc').textContent = '게임별 실행 시간(시:분:초) 로그 및 최근 가장 많이 플레이한 게임 분석';
      secMetrics.classList.add('hidden');
      if (secNetdiskStrip) secNetdiskStrip.classList.add('hidden');
      secCores.classList.add('hidden');
      secBottom.classList.add('hidden');
      secGamelog.classList.remove('hidden');
      if (secNetdisk) secNetdisk.classList.add('hidden');
      renderGameLogDashboard();
    } else if (tab === 'productivity') {
      document.getElementById('top-title').textContent = '뽀모도로-할일-보드';
      document.getElementById('top-desc').textContent = '집중 타이머 & 할 일 체크리스트';
      secMetrics.classList.add('hidden');
      if (secNetdiskStrip) secNetdiskStrip.classList.add('hidden');
      secCores.classList.add('hidden');
      secBottom.classList.remove('hidden');
      secGamelog.classList.add('hidden');
      if (secNetdisk) secNetdisk.classList.add('hidden');
      secBottom.style.gridTemplateColumns = 'minmax(0, 1fr)';
      cardProc.classList.add('hidden');
      cardProd.classList.remove('hidden');
    }
  }

  function setGameLogPeriod(period) {
    gameLogPeriod = period;
    ['7d', '30d', 'today', 'all'].forEach(p => {
      const btn = document.getElementById('gl-period-' + p);
      if (btn) btn.classList.toggle('active', p === period);
    });
    renderGameLogDashboard();
  }

  async function deleteGameLogItem(id) {
    try {
      await apiFetch('/api/delete_game_log?id=' + encodeURIComponent(id), { method: 'POST' });
      showToast('🗑️ 선택한 게임 플레이 기록을 삭제했습니다.');
      fetchStats();
    } catch (e) {
      showToast('⚠️ 기록 삭제 중 오류가 발생했습니다.');
    }
  }

  async function clearAllGameLogs() {
    if (!latestGameLogs || latestGameLogs.length === 0) {
      showToast('ℹ️ 삭제할 게임 플레이 기록이 없습니다.');
      return;
    }
    try {
      await apiFetch('/api/delete_game_log?id=all', { method: 'POST' });
      showToast('🗑️ 모든 게임 플레이 로그 기록을 초기화했습니다.');
      fetchStats();
    } catch (e) {
      showToast('⚠️ 기록 초기화 중 오류가 발생했습니다.');
    }
  }

  function renderNetDiskDashboard() {
    if (!lastStatsData || !lastStatsData.raw) return;
    const d = lastStatsData.raw;
    const net = d.net || {};
    const diskIo = d.disk_io || {};
    const disks = d.disks || [];

    const rxMbs = Number(net.rx_mb_s || 0);
    const txMbs = Number(net.tx_mb_s || 0);
    const rxMbps = Number(net.rx_mbps || 0);
    const txMbps = Number(net.tx_mbps || 0);
    const rxTotalGb = Number(net.rx_total_gb || 0);
    const txTotalGb = Number(net.tx_total_gb || 0);
    const pingMs = Number(net.ping_ms || 0);
    const jitterMs = Number(net.jitter_ms || 0);
    const online = net.online !== false;
    const diskReadMbs = Number(diskIo.read_mb_s || 0);
    const diskWriteMbs = Number(diskIo.write_mb_s || 0);
    const diskTotalMbs = diskReadMbs + diskWriteMbs;

    // 1. 상단 4개 카드 업데이트
    document.getElementById('nd-iface-badge').textContent = net.iface || 'Ethernet';
    document.getElementById('nd-rx-mbs').textContent = `${rxMbs.toFixed(2)} MB/s`;
    document.getElementById('nd-rx-mbps').textContent = `${rxMbps.toFixed(1)} Mbps`;
    document.getElementById('nd-rx-peak-pill').textContent = `최고: ${peakNetRxMbs.toFixed(2)} MB/s`;
    document.getElementById('nd-rx-total-pill').textContent = `누적 수신: ${rxTotalGb.toFixed(2)} GB`;
    const rxScale = Math.max(5, ...netRxHistory);
    drawChart('nd-rx-canvas', netRxHistory, rxScale, '#00b8ff', 'rgba(0, 184, 255, 0.18)');

    document.getElementById('nd-tx-mbs').textContent = `${txMbs.toFixed(2)} MB/s`;
    document.getElementById('nd-tx-mbps').textContent = `${txMbps.toFixed(1)} Mbps`;
    document.getElementById('nd-tx-peak-pill').textContent = `최고: ${peakNetTxMbs.toFixed(2)} MB/s`;
    document.getElementById('nd-tx-total-pill').textContent = `누적 송신: ${txTotalGb.toFixed(2)} GB`;
    const txScale = Math.max(2, ...netTxHistory);
    drawChart('nd-tx-canvas', netTxHistory, txScale, lastStatsData.accentHex, `rgba(${lastStatsData.accentRgb}, 0.18)`);

    const pingStatusBadge = document.getElementById('nd-ping-status-badge');
    const pingValEl = document.getElementById('nd-ping-ms');
    if (!online) {
      pingStatusBadge.textContent = '연결 끊김 🔴';
      pingStatusBadge.style.color = 'var(--red)';
      pingValEl.textContent = '오프라인';
      pingValEl.style.color = 'var(--red)';
    } else {
      pingValEl.textContent = `${pingMs.toFixed(1)} ms`;
      if (net.is_game_ping) {
        if (pingMs < 45) {
          pingStatusBadge.textContent = '인게임 최적 🟢';
          pingStatusBadge.style.color = 'var(--neon-green)';
          pingValEl.style.color = 'var(--neon-green)';
        } else if (pingMs < 115) {
          pingStatusBadge.textContent = '인게임 양호 🟡';
          pingStatusBadge.style.color = 'var(--yellow)';
          pingValEl.style.color = 'var(--yellow)';
        } else {
          pingStatusBadge.textContent = '로비/대기 중 🌐';
          pingStatusBadge.style.color = 'var(--cyan)';
          pingValEl.style.color = 'var(--cyan)';
        }
      } else {
        if (pingMs < 35) {
          pingStatusBadge.textContent = '쾌적 🟢';
          pingStatusBadge.style.color = 'var(--neon-green)';
          pingValEl.style.color = 'var(--neon-green)';
        } else if (pingMs < 80) {
          pingStatusBadge.textContent = '양호 🟡';
          pingStatusBadge.style.color = 'var(--yellow)';
          pingValEl.style.color = 'var(--yellow)';
        } else {
          pingStatusBadge.textContent = '지연 주의 🔴';
          pingStatusBadge.style.color = 'var(--red)';
          pingValEl.style.color = 'var(--red)';
        }
      }
    }
    document.getElementById('nd-jitter-ms').textContent = `Jitter: ${jitterMs.toFixed(1)} ms`;
    const validPings = pingHistory.filter(v => v > 0);
    const avgPing = validPings.length > 0 ? validPings.reduce((a, b) => a + b, 0) / validPings.length : 0;
    document.getElementById('nd-ping-avg-pill').textContent = `60초 평균: ${avgPing.toFixed(1)} ms`;

    const pingCardTitle = document.getElementById('nd-ping-card-title');
    if (pingCardTitle) {
      if (net.is_game_ping) {
        const isIngame = pingMs < 115.0;
        pingCardTitle.textContent = isIngame ? '🎮 인게임 서버 핑 (In-Game Ping)' : '🎮 게임 로비/대기 핑 (Lobby Ping)';
      } else {
        pingCardTitle.textContent = '📡 네트워크 핑 (Ping)';
      }
    }

    const pingTargetPill = document.getElementById('nd-ping-target-pill');
    if (pingTargetPill) {
      pingTargetPill.textContent = net.ping_target || '1.1.1.1';
      if (net.is_game_ping) {
        pingTargetPill.style.color = 'var(--neon-green)';
        pingTargetPill.style.borderColor = 'rgba(0, 200, 117, 0.45)';
        pingTargetPill.style.background = 'rgba(0, 200, 117, 0.12)';
        pingTargetPill.style.fontWeight = '800';
      } else {
        pingTargetPill.style.color = '';
        pingTargetPill.style.borderColor = '';
        pingTargetPill.style.background = '';
        pingTargetPill.style.fontWeight = '';
      }
    }
    const pingScale = Math.max(50, ...pingHistory);
    drawChart('nd-ping-canvas', pingHistory, pingScale, '#00c875', 'rgba(0, 200, 117, 0.16)');

    document.getElementById('nd-disk-count-badge').textContent = `${disks.length}개 드라이브`;
    document.getElementById('nd-disk-total-mbs').textContent = `${diskTotalMbs.toFixed(2)} MB/s`;
    document.getElementById('nd-disk-rw-sub').textContent = `R ${diskReadMbs.toFixed(1)} / W ${diskWriteMbs.toFixed(1)}`;
    document.getElementById('nd-disk-read-pill').textContent = `읽기(R): ${diskReadMbs.toFixed(2)} MB/s`;
    document.getElementById('nd-disk-write-pill').textContent = `쓰기(W): ${diskWriteMbs.toFixed(2)} MB/s`;
    const diskScale = Math.max(10, ...diskIoHistory);
    drawChart('nd-disk-canvas', diskIoHistory, diskScale, '#e66700', 'rgba(230, 103, 0, 0.18)');

    // 2. 좌측 로컬 디스크 드라이브 목록 렌더링
    let sumTotalGb = 0;
    let sumUsedGb = 0;
    disks.forEach(dk => {
      sumTotalGb += Number(dk.total_gb || 0);
      sumUsedGb += Number(dk.used_gb || 0);
    });
    const sumAvailGb = Math.max(0, sumTotalGb - sumUsedGb);
    document.getElementById('nd-total-storage-badge').textContent =
      `총 ${sumUsedGb.toFixed(0)} / ${sumTotalGb.toFixed(0)} GB 사용 (여유 ${sumAvailGb.toFixed(0)} GB)`;

    const drivesListEl = document.getElementById('nd-drives-list');
    if (disks.length === 0) {
      drivesListEl.innerHTML = `<div class="empty-state-box">마운트된 로컬 디스크 드라이브 정보가 없습니다.</div>`;
    } else {
      drivesListEl.innerHTML = disks.map(dk => {
        const pct = Math.min(100, Math.max(0, Number(dk.used_pct || 0)));
        const barColor = pct >= 90 ? 'var(--red)' : (pct >= 78 ? 'var(--orange)' : 'var(--brand)');
        const kindBadgeColor = dk.kind === 'SSD' ? 'var(--neon-green)' : 'var(--text-muted)';
        const label = dk.name ? `${dk.mount} (${dk.name})` : dk.mount;
        return `
          <div class="rank-item">
            <div class="rank-top-row">
              <div class="rank-name-wrap">
                <span class="rank-badge" style="color:${kindBadgeColor}">💽 ${escapeHtml(dk.kind || 'Drive')}</span>
                <span class="rank-title">${escapeHtml(label)}</span>
                <span class="badge">${escapeHtml(dk.fs || 'NTFS')}</span>
              </div>
              <span class="rank-time-hms" style="color:${barColor}">${pct.toFixed(1)}%</span>
            </div>
            <div class="progress-track" style="height: 9px;">
              <div class="progress-fill" style="width: ${pct.toFixed(1)}%; background-color: ${barColor};"></div>
            </div>
            <div class="rank-meta-row">
              <span>사용 중: <strong>${Number(dk.used_gb).toFixed(1)} GB</strong> / 전체 <strong>${Number(dk.total_gb).toFixed(1)} GB</strong></span>
              <span style="color: var(--neon-green); font-weight: 700;">여유 공간: ${Number(dk.avail_gb).toFixed(1)} GB</span>
            </div>
          </div>
        `;
      }).join('');
    }

    // 3. 우측 네트워크 인터페이스 배지 + 디스크 I/O 상위 프로세스 테이블 렌더링
    const ifaces = net.interfaces || [];
    const ifacesEl = document.getElementById('nd-ifaces-summary');
    if (ifacesEl) {
      ifacesEl.innerHTML = ifaces.map(ifc => `
        <span class="stat-pill" style="padding: 4px 9px;">
          🌐 <strong>${escapeHtml(ifc.name)}</strong>: ↓ ${Number(ifc.rx_mb_s).toFixed(2)} MB/s • ↑ ${Number(ifc.tx_mb_s).toFixed(2)} MB/s (누적 ${(Number(ifc.rx_total_gb) + Number(ifc.tx_total_gb)).toFixed(2)} GB)
        </span>
      `).join('');
    }

    const diskProcs = [...latestProcesses]
      .sort((a, b) => {
        const ioA = Number(a.disk_r_mb_s || 0) + Number(a.disk_w_mb_s || 0);
        const ioB = Number(b.disk_r_mb_s || 0) + Number(b.disk_w_mb_s || 0);
        if (Math.abs(ioB - ioA) > 0.001) return ioB - ioA;
        return (b.mem_mb || 0) - (a.mem_mb || 0);
      })
      .slice(0, 25);

    const tbody = document.getElementById('nd-disk-procs-tbody');
    if (tbody) {
      tbody.innerHTML = diskProcs.map(p => {
        const r = Number(p.disk_r_mb_s || 0);
        const w = Number(p.disk_w_mb_s || 0);
        return `
          <tr oncontextmenu="showProcContextMenu(event, ${p.pid}, '${escapeJsStr(p.name)}')" title="우클릭하여 프로세스 메뉴 열기">
            <td style="color: var(--text-muted); font-variant-numeric: tabular-nums;">${p.pid}</td>
            <td style="font-weight: 700;"><span class="proc-name-cell">${procIconHtml(p.name, 16)}<span>${escapeHtml(p.name)}</span></span></td>
            <td style="color: ${r > 0.05 ? 'var(--neon-green)' : 'var(--text-muted)'}; font-weight: 700; font-variant-numeric: tabular-nums;">
              ${r.toFixed(2)} MB/s
            </td>
            <td style="color: ${w > 0.05 ? 'var(--orange)' : 'var(--text-muted)'}; font-weight: 700; font-variant-numeric: tabular-nums;">
              ${w.toFixed(2)} MB/s
            </td>
            <td style="font-variant-numeric: tabular-nums; font-size: 12px; color: var(--text-muted);">
              CPU ${p.cpu.toFixed(1)}% • ${p.mem_mb.toFixed(0)} MB
            </td>
          </tr>
        `;
      }).join('');
    }
  }

  function renderGameLogDashboard() {
    const s = lastStatsData;
    const logs = latestGameLogs || [];
    const nowSec = Math.floor(Date.now() / 1000);
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const todayStartSec = Math.floor(todayStart.getTime() / 1000);
    const weekStartSec = nowSec - 7 * 86400;
    const monthStartSec = nowSec - 30 * 86400;

    // 1. 상단 1번 카드: 현재 실행 중인 게임
    const activeBadge = document.getElementById('gl-active-badge');
    const activeTimer = document.getElementById('gl-active-timer');
    const activeFpsEl = document.getElementById('gl-active-fps');
    const activeNameEl = document.getElementById('gl-active-name');

    if (s && s.isGameRunning) {
      activeBadge.textContent = 'LIVE 🔴';
      activeBadge.style.color = 'var(--neon-green)';
      activeTimer.textContent = s.activeRunHMS || '00:00:00';
      activeTimer.style.color = 'var(--neon-green)';
      activeFpsEl.textContent = `${s.activeFps} FPS (${s.activeMs.toFixed(1)} ms)`;
      activeNameEl.textContent = `🎮 ${s.targetLabel}`;
    } else {
      activeBadge.textContent = 'IDLE';
      activeBadge.style.color = 'var(--text-muted)';
      activeTimer.textContent = '00:00:00';
      activeTimer.style.color = 'var(--text-muted)';
      activeFpsEl.textContent = '대기 중';
      activeNameEl.textContent = logs.length > 0 ? `최근 플레이: ${logs[0].name}` : '실행 중인 게임 없음';
    }

    // 2. 기간별 누적 합계 계산
    let todayTotalSecs = 0;
    let weekTotalSecs = 0;
    let allTotalSecs = 0;
    const allGameSet = new Set();

    logs.forEach(item => {
      const dur = Number(item.duration_secs || 0);
      const endTs = Number(item.end_ts || item.start_ts || 0);
      allTotalSecs += dur;
      allGameSet.add(item.name);
      if (endTs >= todayStartSec) todayTotalSecs += dur;
      if (endTs >= weekStartSec) weekTotalSecs += dur;
    });

    document.getElementById('gl-today-time').textContent = formatHMS(todayTotalSecs);
    document.getElementById('gl-week-time').textContent = `최근 7일 합산: ${formatHMS(weekTotalSecs)} (${formatDurationReadable(weekTotalSecs)})`;
    document.getElementById('gl-total-games-badge').textContent = `${allGameSet.size}개 게임`;
    document.getElementById('gl-total-time').textContent = formatHMS(allTotalSecs);
    document.getElementById('gl-total-sessions').textContent = `총 ${logs.length}회 세션`;

    // 3. 선택된 기간(7d / 30d / today / all) 기준 게임별 랭킹 집계
    const periodFiltered = logs.filter(item => {
      const endTs = Number(item.end_ts || item.start_ts || 0);
      if (gameLogPeriod === 'today') return endTs >= todayStartSec;
      if (gameLogPeriod === '7d') return endTs >= weekStartSec;
      if (gameLogPeriod === '30d') return endTs >= monthStartSec;
      return true;
    });

    const gameMap = new Map();
    let periodSumSecs = 0;
    periodFiltered.forEach(item => {
      const dur = Number(item.duration_secs || 0);
      periodSumSecs += dur;
      const itemAvgFps = Number(item.avg_fps || 0);
      const itemLow1Fps = Number(item.low_1pct_fps || 0);
      const itemMaxGpuTemp = Number(item.max_gpu_temp || 0);
      const itemMaxGpuUsage = Number(item.max_gpu_usage || 0);
      const prev = gameMap.get(item.name) || {
        name: item.name,
        exe: item.exe || '',
        totalSecs: 0,
        fpsWeightedSecs: 0,
        fpsWeightedSum: 0,
        low1WeightedSum: 0,
        sessions: 0,
        lastTs: 0,
        maxCpu: 0,
        maxMemMb: 0,
        maxGpuTemp: 0,
        maxGpuUsage: 0,
        active: false
      };
      prev.totalSecs += dur;
      if (itemAvgFps > 0) {
        const w = Math.max(1, dur);
        prev.fpsWeightedSecs += w;
        prev.fpsWeightedSum += itemAvgFps * w;
        prev.low1WeightedSum += (itemLow1Fps > 0 ? itemLow1Fps : itemAvgFps * 0.82) * w;
      }
      prev.sessions += 1;
      prev.lastTs = Math.max(prev.lastTs, Number(item.end_ts || item.start_ts || 0));
      prev.maxCpu = Math.max(prev.maxCpu, Number(item.max_cpu || 0));
      prev.maxMemMb = Math.max(prev.maxMemMb, Number(item.max_mem_mb || 0));
      prev.maxGpuTemp = Math.max(prev.maxGpuTemp, itemMaxGpuTemp);
      prev.maxGpuUsage = Math.max(prev.maxGpuUsage, itemMaxGpuUsage);
      if (item.active) prev.active = true;
      gameMap.set(item.name, prev);
    });

    const rankedGames = Array.from(gameMap.values()).map(g => {
      g.avgFps = g.fpsWeightedSecs > 0 ? (g.fpsWeightedSum / g.fpsWeightedSecs) : 0;
      g.low1Fps = g.fpsWeightedSecs > 0 ? (g.low1WeightedSum / g.fpsWeightedSecs) : 0;
      return g;
    }).sort((a, b) => b.totalSecs - a.totalSecs);

    // 상단 2번 카드: 최근 가장 많이 한 게임 업데이트
    if (rankedGames.length > 0) {
      const top1 = rankedGames[0];
      const sharePct = periodSumSecs > 0 ? ((top1.totalSecs / periodSumSecs) * 100).toFixed(0) : 100;
      document.getElementById('gl-top-share-badge').textContent = `점유율 ${sharePct}%`;
      document.getElementById('gl-top-game-name').textContent = `👑 ${top1.name}`;
      const perfSummary = top1.avgFps > 0
        ? ` • 평균 ${top1.avgFps.toFixed(0)} FPS (1% Low ${top1.low1Fps.toFixed(0)}) • 최고 ${top1.maxGpuTemp.toFixed(0)}°C`
        : '';
      document.getElementById('gl-top-game-time').textContent = `누적 ${formatHMS(top1.totalSecs)} (${top1.sessions}회)${perfSummary}`;
    } else {
      document.getElementById('gl-top-share-badge').textContent = '점유율 0%';
      document.getElementById('gl-top-game-name').textContent = '기록 없음';
      document.getElementById('gl-top-game-time').textContent = '누적 00:00:00 (0회 실행)';
    }

    // 좌측 랭킹 리스트 렌더링
    const rankListEl = document.getElementById('gamelog-ranking-list');
    if (rankedGames.length === 0) {
      rankListEl.innerHTML = `
        <div class="empty-state-box">
          <div style="font-size: 28px;">🎮</div>
          <div style="font-weight: 700; color: var(--text-normal);">선택한 기간에 기록된 게임 플레이 내역이 없습니다</div>
          <div>게임을 실행하면 자동으로 감지되어 <strong>시:분:초(HH:MM:SS)</strong> 단위로 플레이 시간과 <strong>평균 FPS / 1% Low / 최고 GPU 온도</strong>가 자동 기록됩니다.<br>또는 [통합-대시보드]의 상위 프로세스에서 원하는 프로그램을 우클릭해 <strong>FPS 타겟으로 지정</strong>해 보세요!</div>
        </div>
      `;
    } else {
      rankListEl.innerHTML = rankedGames.map((g, idx) => {
        const share = periodSumSecs > 0 ? (g.totalSecs / periodSumSecs) * 100 : 0;
        const rankClass = idx === 0 ? 'top-1' : (idx === 1 ? 'top-2' : (idx === 2 ? 'top-3' : ''));
        const badgeLabel = idx === 0 ? '🥇 1위' : (idx === 1 ? '🥈 2위' : (idx === 2 ? '🥉 3위' : `#${idx + 1}`));
        const lastDateStr = g.active ? '현재 플레이 중 🔴' : formatSessionTimeRange(g.lastTs, g.lastTs, false).split(' ~ ')[0];
        const fpsBadgeHtml = g.avgFps > 0
          ? `<span class="badge" style="color:var(--brand); font-variant-numeric:tabular-nums;">🎯 평균 ${g.avgFps.toFixed(0)} FPS · 1% Low ${g.low1Fps.toFixed(0)}</span>`
          : `<span class="badge" style="color:var(--text-muted)">FPS 집계 대기</span>`;
        const tempColor = g.maxGpuTemp >= 80 ? 'var(--red)' : (g.maxGpuTemp >= 70 ? 'var(--orange)' : 'var(--neon-green)');
        const tempBadgeHtml = g.maxGpuTemp > 0
          ? `<span class="badge" style="color:${tempColor}; font-variant-numeric:tabular-nums;">🌡️ 최고 GPU ${g.maxGpuTemp.toFixed(0)}°C (${g.maxGpuUsage.toFixed(0)}%)</span>`
          : '';
        return `
          <div class="rank-item ${rankClass}">
            <div class="rank-top-row">
              <div class="rank-name-wrap">
                <span class="rank-badge ${idx === 0 ? 'gold' : ''}">${badgeLabel}</span>
                ${g.exe ? procIconHtml(g.exe, 16) : ''}
                <span class="rank-title">${escapeHtml(g.name)}</span>
                ${g.active ? '<span class="badge" style="color:var(--neon-green)">LIVE 🔴</span>' : ''}
              </div>
              <span class="rank-time-hms">${formatHMS(g.totalSecs)}</span>
            </div>
            <div class="progress-track" style="height: 8px;">
              <div class="progress-fill" style="width: ${Math.min(100, share).toFixed(1)}%; background: ${idx === 0 ? 'linear-gradient(90deg, #f59f00, #ff6b00)' : 'var(--brand)'};"></div>
            </div>
            <div style="display:flex; flex-wrap:wrap; gap:6px; margin-top:2px;">
              ${fpsBadgeHtml}
              ${tempBadgeHtml}
              <span class="badge" style="font-variant-numeric:tabular-nums;">피크 CPU ${g.maxCpu.toFixed(0)}% · RAM ${g.maxMemMb.toFixed(0)}MB</span>
            </div>
            <div class="rank-meta-row">
              <span>비중 <strong>${share.toFixed(1)}%</strong> • 총 <strong>${g.sessions}회</strong> 실행 (${formatDurationReadable(g.totalSecs)})</span>
              <span>최근: ${lastDateStr}</span>
            </div>
          </div>
        `;
      }).join('');
    }

    // 우측 세션 히스토리 테이블 렌더링
    const searchQ = (document.getElementById('gamelog-search')?.value || '').trim().toLowerCase();
    const filteredSessions = logs.filter(item => !searchQ || item.name.toLowerCase().includes(searchQ) || (item.exe && item.exe.toLowerCase().includes(searchQ)));
    const tbody = document.getElementById('gamelog-tbody');
    if (filteredSessions.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; padding: 36px 16px; color: var(--text-muted);">
            아직 저장된 게임 실행 세션 로그가 없습니다. 게임을 실행하면 실시간으로 시:분:초 및 평균 FPS / 1% Low / 최고 GPU 온도가 자동 기록됩니다.
          </td>
        </tr>
      `;
    } else {
      tbody.innerHTML = filteredSessions.map(item => {
        const avgFps = Number(item.avg_fps || 0);
        const low1Fps = Number(item.low_1pct_fps || 0);
        const maxGpuTemp = Number(item.max_gpu_temp || 0);
        const maxGpuUsage = Number(item.max_gpu_usage || 0);
        const tempColor = maxGpuTemp >= 80 ? 'var(--red)' : (maxGpuTemp >= 70 ? 'var(--orange)' : 'var(--neon-green)');
        return `
        <tr style="${item.active ? 'background-color: rgba(0, 200, 117, 0.08);' : ''}">
          <td style="font-variant-numeric: tabular-nums; color: var(--text-muted); font-size: 12px;">
            ${formatSessionTimeRange(item.start_ts, item.end_ts, item.active)}
          </td>
          <td style="font-weight: 700;">
            <span class="proc-name-cell">
              ${item.exe ? procIconHtml(item.exe, 16) : ''}
              <span>${escapeHtml(item.name)}</span>
              ${item.active ? '<span class="badge" style="color:var(--neon-green); margin-left:4px;">실행 중</span>' : ''}
            </span>
          </td>
          <td style="font-variant-numeric: tabular-nums; font-weight: 800; color: var(--neon-green);">
            ⏱️ ${formatHMS(item.duration_secs)}
            <span style="font-weight: 500; font-size: 11px; color: var(--text-muted); margin-left: 4px;">(${formatDurationReadable(item.duration_secs)})</span>
          </td>
          <td style="font-variant-numeric: tabular-nums; font-size: 12px;">
            ${avgFps > 0
              ? `평균 <strong style="color:var(--brand)">${avgFps.toFixed(0)} FPS</strong> <span style="color:var(--text-muted)">• 1% Low</span> <strong style="color:var(--orange)">${low1Fps.toFixed(0)}</strong>`
              : `<span style="color:var(--text-muted)">집계 대기</span>`}
          </td>
          <td style="font-variant-numeric: tabular-nums; font-size: 12px;">
            ${maxGpuTemp > 0
              ? `🌡️ <strong style="color:${tempColor}">${maxGpuTemp.toFixed(0)}°C</strong> <span style="color:var(--text-muted)">(GPU ${maxGpuUsage.toFixed(0)}%)</span><br>`
              : ''}
            <span style="font-size:11px; color:var(--text-muted);">CPU <strong style="color:var(--text-normal)">${Number(item.max_cpu || 0).toFixed(1)}%</strong> • RAM <strong style="color:var(--text-normal)">${Number(item.max_mem_mb || 0).toFixed(0)}MB</strong></span>
          </td>
          <td style="text-align: right;">
            <button class="todo-del" onclick="deleteGameLogItem('${escapeJsStr(item.id)}')" title="이 세션 기록 삭제">삭제</button>
          </td>
        </tr>
      `}).join('');
    }
  }

  // 캔버스 영역 차트 그리기
  function drawChart(canvasId, data, maxVal, strokeColor, fillColor) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    const gridColor = getComputedStyle(document.body).getPropertyValue('--grid-line').trim() || 'rgba(128,128,128,0.1)';
    ctx.strokeStyle = gridColor;
    ctx.lineWidth = 1;
    [0.25, 0.5, 0.75].forEach(r => {
      ctx.beginPath();
      ctx.moveTo(0, h * r);
      ctx.lineTo(w, h * r);
      ctx.stroke();
    });

    if (data.length < 2) return;
    const step = w / (data.length - 1);
    const scaleMax = Math.max(10, maxVal);

    ctx.beginPath();
    data.forEach((val, i) => {
      const x = i * step;
      const ratio = Math.min(1, Math.max(0, val / scaleMax));
      const y = h - ratio * (h - 12) - 4;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = 2.2;
    ctx.stroke();

    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = fillColor;
    ctx.fill();
  }

  function onSelectTargetProcess() {
    selectedTargetProc = document.getElementById('game-select').value;
    fetchStats();
  }

  function updateProcessDropdown() {
    const sel = document.getElementById('game-select');
    const current = sel.value;
    const topNames = [...new Set(latestProcesses.slice(0, 15).map(p => p.name))];
    let html = '<option value="auto">🎯 게임 자동 감지</option>';
    topNames.forEach(name => {
      const selected = name === current ? 'selected' : '';
      html += `<option value="${escapeHtml(name)}" ${selected}>📌 ${escapeHtml(name)}</option>`;
    });
    sel.innerHTML = html;
  }

  function escapeJsStr(s) {
    return String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '&quot;');
  }

  function renderProcesses() {
    const q = document.getElementById('proc-search').value.trim().toLowerCase();
    const tbody = document.getElementById('proc-tbody');
    const filtered = latestProcesses.filter(p => !q || p.name.toLowerCase().includes(q));

    filtered.sort((a, b) => {
      let cmp = 0;
      if (procSortKey === 'name') {
        cmp = a.name.localeCompare(b.name, 'ko', { sensitivity: 'base' });
      } else {
        cmp = (a[procSortKey] || 0) - (b[procSortKey] || 0);
      }
      return procSortAsc ? cmp : -cmp;
    });

    tbody.innerHTML = filtered.map(p => `
      <tr oncontextmenu="showProcContextMenu(event, ${p.pid}, '${escapeJsStr(p.name)}')" title="우클릭하여 프로세스 메뉴 열기">
        <td style="color: var(--text-muted); font-variant-numeric: tabular-nums;">${p.pid}</td>
        <td style="font-weight: 600;"><span class="proc-name-cell">${procIconHtml(p.name, 16)}<span>${escapeHtml(p.name)}</span></span></td>
        <td style="color: ${p.cpu > 25 ? 'var(--orange)' : 'var(--brand)'}; font-weight: 600; font-variant-numeric: tabular-nums;">${p.cpu.toFixed(1)}%</td>
        <td style="font-variant-numeric: tabular-nums;">${p.mem_mb.toFixed(1)} MB</td>
      </tr>
    `).join('');
  }

  function getWindowBoundsQuery() {
    const x = Math.round(window.screenX ?? window.screenLeft ?? 100);
    const y = Math.round(window.screenY ?? window.screenTop ?? 100);
    const w = Math.round(window.outerWidth || 1360);
    const h = Math.round(window.outerHeight || 880);
    const curFps = Math.round(compositorFps || 0);
    const curLow1 = Math.round(lastStatsData && lastStatsData.low1Pct ? lastStatsData.low1Pct : curFps * 0.85);
    return `x=${x}&y=${y}&w=${w}&h=${h}&mini=${isMiniHudMode ? '1' : '0'}&fps=${curFps}&low1=${curLow1}&mode=${encodeURIComponent(themeOverride)}&target=${encodeURIComponent(selectedTargetProc)}&token=${encodeURIComponent(SESSION_TOKEN)}`;
  }

  // ==================== 원클릭 컴팩트 미니 HUD 모드 ====================
  const INITIAL_MINIHUD_DATA = /*__COREFLOW_INITIAL_MINIHUD__*/null;
  let isMiniHudMode = false;
  let miniHudTopmost = true;
  let miniHudWideLayout = false;
  let savedNormalBounds = (function() {
    if (INITIAL_MINIHUD_DATA && INITIAL_MINIHUD_DATA.normal_w >= 900 && INITIAL_MINIHUD_DATA.normal_h >= 550) {
      return {
        x: INITIAL_MINIHUD_DATA.normal_x ?? 120,
        y: INITIAL_MINIHUD_DATA.normal_y ?? 80,
        w: INITIAL_MINIHUD_DATA.normal_w,
        h: INITIAL_MINIHUD_DATA.normal_h
      };
    }
    try {
      const raw = localStorage.getItem('coreflow_normal_bounds');
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed && parsed.w >= 900 && parsed.h >= 550) {
          return parsed;
        }
      }
    } catch (e) {}
    return { x: 120, y: 80, w: 1360, h: 880 };
  })();

  function persistNormalBounds(nb) {
    if (!nb || nb.w < 900 || nb.h < 550) return;
    savedNormalBounds = {
      x: (nb.x > -10000) ? nb.x : 120,
      y: (nb.y > -10000) ? nb.y : 80,
      w: Math.max(960, Math.round(nb.w)),
      h: Math.max(640, Math.round(nb.h))
    };
    try {
      localStorage.setItem('coreflow_normal_bounds', JSON.stringify(savedNormalBounds));
    } catch (e) {}
  }

  function resizeNativeAppWindow(w, h, x, y) {
    try {
      if (typeof w === 'number' && typeof h === 'number' && w >= 220 && h >= 110) {
        window.resizeTo(Math.round(w), Math.round(h));
      }
      if (typeof x === 'number' && typeof y === 'number' && x > -10000 && y > -10000) {
        window.moveTo(Math.round(x), Math.round(y));
      }
    } catch (e) {}
  }

  function getMiniHudTargetSize() {
    const hudKeys = ['hudFps', 'hudCpu', 'hudGpu', 'hudRam', 'hudNet', 'hudTimer'];
    const visibleCount = (typeof uiPrefs !== 'undefined' && uiPrefs)
      ? Math.max(1, hudKeys.filter(k => uiPrefs[k] !== false).length)
      : 6;
    if (miniHudWideLayout) {
      const cols = visibleCount;
      const rows = 1;
      const w = Math.max(240, Math.min(820, visibleCount * 126 + 24));
      const h = 168;
      return { w, h, cols, rows, visibleCount };
    } else {
      if (visibleCount <= 1) return { w: 240, h: 168, cols: 1, rows: 1, visibleCount };
      if (visibleCount === 2) return { w: 340, h: 168, cols: 2, rows: 1, visibleCount };
      if (visibleCount === 3) return { w: 450, h: 168, cols: 3, rows: 1, visibleCount };
      if (visibleCount === 4) return { w: 360, h: 265, cols: 2, rows: 2, visibleCount };
      return { w: 450, h: 265, cols: 3, rows: 2, visibleCount };
    }
  }

  async function syncMiniHudState(isMini) {
    const target = getMiniHudTargetSize();
    const curX = Math.round(window.screenX ?? window.screenLeft ?? 0);
    const curY = Math.round(window.screenY ?? window.screenTop ?? 0);
    const curW = isMini ? target.w : Math.round(window.outerWidth || target.w);
    const curH = isMini ? target.h : Math.round(window.outerHeight || target.h);
    const nb = (savedNormalBounds && savedNormalBounds.w >= 900 && savedNormalBounds.h >= 550)
      ? savedNormalBounds
      : { x: 120, y: 80, w: 1360, h: 880 };
    const params = new URLSearchParams({
      mini: isMini ? '1' : '0',
      wide: miniHudWideLayout ? '1' : '0',
      topmost: miniHudTopmost ? '1' : '0',
      mx: curX,
      my: curY,
      mw: curW,
      mh: curH,
      nx: nb.x,
      ny: nb.y,
      nw: nb.w,
      nh: nb.h
    });
    try {
      await apiFetch(`/api/minihud_state?${params.toString()}`, { method: 'POST' });
    } catch (e) {
      console.error(e);
    }
  }

  function applyMiniHudSavedObj(st, hasMiniParam) {
    if (st && typeof st.wide === 'boolean') {
      if (typeof uiPrefs !== 'undefined' && uiPrefs && typeof uiPrefs.hudLayoutWide === 'boolean') {
        miniHudWideLayout = uiPrefs.hudLayoutWide;
      } else {
        miniHudWideLayout = Boolean(st.wide);
      }
    }
    if (st && typeof st.topmost === 'boolean') {
      if (typeof uiPrefs !== 'undefined' && uiPrefs && typeof uiPrefs.hudTopmost === 'boolean') {
        miniHudTopmost = uiPrefs.hudTopmost;
      } else {
        miniHudTopmost = st.topmost !== false;
      }
    }
    if (st && st.normal_w >= 900 && st.normal_h >= 550) {
      persistNormalBounds({
        x: st.normal_x ?? 120,
        y: st.normal_y ?? 80,
        w: st.normal_w,
        h: st.normal_h
      });
    }
    if (hasMiniParam || (st && st.is_mini)) {
      isMiniHudMode = true;
      const overlay = document.getElementById('mini-hud-overlay');
      if (overlay) {
        overlay.classList.remove('hidden');
        overlay.classList.toggle('layout-wide', miniHudWideLayout);
      }
      updateMiniHudControlsUI();
      applyUiPrefs(false);
      if (lastStatsData) {
        renderMiniHud();
      }
    } else if (window.outerWidth >= 900 && window.outerHeight >= 550) {
      persistNormalBounds({
        x: Math.round(window.screenX ?? window.screenLeft ?? 120),
        y: Math.round(window.screenY ?? window.screenTop ?? 80),
        w: Math.round(window.outerWidth),
        h: Math.round(window.outerHeight)
      });
    }
  }

  async function initMiniHudModeFromSaved() {
    const urlParams = new URLSearchParams(window.location.search);
    const hasMiniParam = urlParams.get('mini') === '1';
    // 1. 서버가 HTML에 주입한 초기 미니 HUD 상태를 즉시 동기 반영하여 fetchStats()가 잘못된 창 크기를 덮어쓰지 않도록 보호
    if (INITIAL_MINIHUD_DATA || hasMiniParam) {
      applyMiniHudSavedObj(INITIAL_MINIHUD_DATA, hasMiniParam);
    }
    try {
      const res = await apiFetch('/api/minihud_state');
      const st = await res.json();
      applyMiniHudSavedObj(st, hasMiniParam);
    } catch (e) {}
  }

  async function enterMiniHudMode() {
    if (isMiniHudMode) return;
    if (typeof uiPrefs !== 'undefined' && uiPrefs) {
      miniHudWideLayout = Boolean(uiPrefs.hudLayoutWide);
      miniHudTopmost = uiPrefs.hudTopmost !== false;
    }
    if (window.outerWidth >= 900 && window.outerHeight >= 550) {
      persistNormalBounds({
        x: Math.round(window.screenX ?? window.screenLeft ?? 120),
        y: Math.round(window.screenY ?? window.screenTop ?? 80),
        w: Math.round(window.outerWidth),
        h: Math.round(window.outerHeight)
      });
    }
    isMiniHudMode = true;
    closeDetailView();
    closeRecordAnalysis();
    closeAlertSettings();
    closeUiSettingsModal();
    closeHelpModal();

    const overlay = document.getElementById('mini-hud-overlay');
    if (overlay) {
      overlay.classList.remove('hidden');
      overlay.classList.toggle('layout-wide', miniHudWideLayout);
    }
    updateMiniHudControlsUI();
    applyUiPrefs(false);
    renderMiniHud();

    const target = getMiniHudTargetSize();
    resizeNativeAppWindow(target.w, target.h);
    try {
      await apiFetch(`/api/window_ctl?topmost=${miniHudTopmost ? '1' : '0'}&w=${target.w}&h=${target.h}`, { method: 'POST' });
    } catch (e) {
      console.error(e);
    }
    syncMiniHudState(true);
  }

  async function exitMiniHudMode() {
    if (!isMiniHudMode) return;
    isMiniHudMode = false;
    const overlay = document.getElementById('mini-hud-overlay');
    if (overlay) overlay.classList.add('hidden');

    // URL에 ?mini=1 쿼리가 남아있으면 새로고침 시 다시 미니 HUD로 들어가는 현상 제거
    try {
      if (window.location.search.includes('mini=')) {
        window.history.replaceState(null, '', window.location.pathname);
      }
    } catch (e) {}

    const rawB = (savedNormalBounds && savedNormalBounds.w >= 900 && savedNormalBounds.h >= 550)
      ? savedNormalBounds
      : { x: 120, y: 80, w: 1360, h: 880 };
    const targetW = Math.max(960, Math.round(rawB.w || 1360));
    const targetH = Math.max(640, Math.round(rawB.h || 880));
    const targetX = (typeof rawB.x === 'number' && rawB.x > -10000) ? Math.round(rawB.x) : 120;
    const targetY = (typeof rawB.y === 'number' && rawB.y > -10000) ? Math.round(rawB.y) : 80;

    // 1. 브라우저 자체 창 제어(window.resizeTo / moveTo) 즉시 실행 + Win32 SetWindowPos 병행 호출
    resizeNativeAppWindow(targetW, targetH, targetX, targetY);
    try {
      await apiFetch(`/api/window_ctl?topmost=0&x=${targetX}&y=${targetY}&w=${targetW}&h=${targetH}`, { method: 'POST' });
    } catch (e) {
      console.error(e);
    }
    // 2. 120ms 후 창 크기가 복원되지 않았을 경우 재시도 보장 및 대시보드 레이아웃/차트 재정렬
    setTimeout(() => {
      if (!isMiniHudMode && (window.outerWidth < 850 || window.outerHeight < 520)) {
        resizeNativeAppWindow(targetW, targetH, targetX, targetY);
        apiFetch(`/api/window_ctl?topmost=0&x=${targetX}&y=${targetY}&w=${targetW}&h=${targetH}`, { method: 'POST' }).catch(() => {});
      }
      applyUiPrefs(false);
      applyDashboardViewMode();
      if (lastStatsData) {
        fetchStats();
      }
    }, 120);
    applyUiPrefs(false);
    applyDashboardViewMode();
    syncMiniHudState(false);
  }

  async function toggleMiniHudTopmost() {
    miniHudTopmost = !miniHudTopmost;
    if (typeof uiPrefs !== 'undefined' && uiPrefs) {
      uiPrefs.hudTopmost = miniHudTopmost;
      saveUiPrefs();
      applyUiPrefs(false);
    }
    updateMiniHudControlsUI();
    try {
      await apiFetch(`/api/window_ctl?topmost=${miniHudTopmost ? '1' : '0'}`, { method: 'POST' });
      showToast(miniHudTopmost ? '📌 창 항상 위 고정(ON)' : '📌 창 항상 위 고정 해제(OFF)');
    } catch (e) {
      console.error(e);
    }
    syncMiniHudState(isMiniHudMode);
  }

  async function toggleMiniHudLayout() {
    miniHudWideLayout = !miniHudWideLayout;
    if (typeof uiPrefs !== 'undefined' && uiPrefs) {
      uiPrefs.hudLayoutWide = miniHudWideLayout;
      saveUiPrefs();
    }
    const overlay = document.getElementById('mini-hud-overlay');
    if (overlay) overlay.classList.toggle('layout-wide', miniHudWideLayout);
    updateMiniHudControlsUI();
    applyUiPrefs(false);

    const target = getMiniHudTargetSize();
    if (isMiniHudMode) {
      resizeNativeAppWindow(target.w, target.h);
    }
    try {
      await apiFetch(`/api/window_ctl?topmost=${miniHudTopmost ? '1' : '0'}&w=${target.w}&h=${target.h}`, { method: 'POST' });
    } catch (e) {
      console.error(e);
    }
    syncMiniHudState(isMiniHudMode);
  }

  function updateMiniHudControlsUI() {
    const topBtn = document.getElementById('mh-topmost-btn');
    if (topBtn) {
      topBtn.textContent = miniHudTopmost ? '📌 항상 위 ON' : '📌 항상 위 OFF';
      topBtn.classList.toggle('active', miniHudTopmost);
    }
    const layBtn = document.getElementById('mh-layout-btn');
    if (layBtn) {
      layBtn.textContent = miniHudWideLayout ? '📐 박스형 전환' : '📐 가로바 전환';
    }
  }

  function renderMiniHud() {
    if (!isMiniHudMode || !lastStatsData) return;
    const s = lastStatsData;
    const d = s.raw || {};
    const g = d.gpu || {};
    const net = d.net || {};
    const diskIo = d.disk_io || {};

    const gameBadge = document.getElementById('mh-game-badge');
    if (gameBadge) {
      gameBadge.textContent = s.isGameRunning
        ? `🎮 ${s.targetLabel} (${s.activeRunHMS})`
        : 'IDLE 대기 중';
      gameBadge.style.color = s.isGameRunning ? 'var(--neon-green)' : 'var(--text-muted)';
    }

    // 1. FPS
    document.getElementById('mh-fps-val').textContent = s.isGameRunning ? `${s.activeFps} FPS` : '0 FPS';
    document.getElementById('mh-fps-low').textContent = `1%L ${s.low1Pct}`;
    document.getElementById('mh-fps-bar').style.width = s.isGameRunning ? `${Math.min(100, (s.activeFps / 165) * 100)}%` : '0%';
    document.getElementById('mh-fps-sub').textContent = s.isGameRunning ? `${s.activeMs.toFixed(1)} ms • LIVE` : '실행 게임 없음';

    // 2. CPU
    const cpuTempC = typeof d.cpu_temp_c === 'number' && d.cpu_temp_c > 0 ? d.cpu_temp_c : null;
    const maxCore = (d.cores && d.cores.length) ? Math.max(...d.cores) : d.cpu;
    if (cpuTempC !== null) {
      document.getElementById('mh-cpu-val').innerHTML = `${d.cpu.toFixed(0)}% <span style="font-size:0.75em; opacity:0.85; font-weight:700;">/ ${cpuTempC.toFixed(0)}°C</span>`;
    } else {
      document.getElementById('mh-cpu-val').innerHTML = `${d.cpu.toFixed(0)}% <span style="font-size:0.75em; opacity:0.5; font-weight:600;">/ -</span>`;
    }
    document.getElementById('mh-cpu-core').textContent = `${(d.cores || []).length}코어`;
    document.getElementById('mh-cpu-bar').style.width = `${Math.min(100, d.cpu)}%`;
    document.getElementById('mh-cpu-sub').textContent = `최고 코어 ${maxCore.toFixed(0)}%`;

    // 3. GPU
    if (s.tempC > 0) {
      document.getElementById('mh-gpu-val').innerHTML = `${s.gpuUsage.toFixed(0)}% <span style="font-size:0.75em; opacity:0.85; font-weight:700;">/ ${s.tempC.toFixed(0)}°C</span>`;
    } else {
      document.getElementById('mh-gpu-val').innerHTML = `${s.gpuUsage.toFixed(0)}% <span style="font-size:0.75em; opacity:0.5; font-weight:600;">/ -</span>`;
    }
    const tempEl = document.getElementById('mh-gpu-temp');
    tempEl.textContent = `${s.tempC.toFixed(0)}°C`;
    tempEl.style.color = s.tempC >= 78 ? 'var(--red)' : (s.tempC >= 65 ? 'var(--yellow)' : 'var(--neon-green)');
    document.getElementById('mh-gpu-bar').style.width = `${Math.min(100, s.gpuUsage)}%`;
    document.getElementById('mh-gpu-sub').textContent = `VRAM ${s.vramUsedGb.toFixed(1)}G • ${(g.power_w || 0).toFixed(0)}W`;

    // 4. RAM
    document.getElementById('mh-ram-val').textContent = `${s.memPct.toFixed(1)}%`;
    document.getElementById('mh-ram-swap').textContent = `Swap ${s.swapGb.toFixed(1)}G`;
    document.getElementById('mh-ram-bar').style.width = `${Math.min(100, s.memPct)}%`;
    document.getElementById('mh-ram-sub').textContent = `${s.usedGb.toFixed(1)} / ${s.totalGb.toFixed(0)} GB`;

    // 5. NET & PING & DISK I/O
    const pingMs = Number(net.ping_ms || 0);
    const rxMbs = Number(net.rx_mb_s || 0);
    const txMbs = Number(net.tx_mb_s || 0);
    const diskTot = Number(diskIo.read_mb_s || 0) + Number(diskIo.write_mb_s || 0);
    const mhNetLabel = document.getElementById('mh-net-label');
    if (mhNetLabel) {
      if (net.is_game_ping) {
        const isIngame = pingMs < 115.0;
        mhNetLabel.textContent = isIngame ? '🎮 IN-GAME' : '🎮 LOBBY';
        mhNetLabel.style.color = isIngame ? 'var(--neon-green)' : 'var(--cyan)';
      } else {
        mhNetLabel.textContent = '🌐 NET/PING';
        mhNetLabel.style.color = '';
      }
    }
    document.getElementById('mh-net-val').textContent = net.online === false ? '오프라인' : `${pingMs.toFixed(1)} ms`;
    document.getElementById('mh-net-down').textContent = `↓ ${rxMbs.toFixed(2)} MB/s`;
    document.getElementById('mh-net-up').textContent = `↑ ${txMbs.toFixed(2)} MB/s`;
    document.getElementById('mh-disk-io').textContent = `💽 ${diskTot.toFixed(1)}M/s`;

    // 6. 플레이 시간 & 뽀모도로
    const pm = String(Math.floor(pomoRemaining / 60)).padStart(2, '0');
    const ps = String(pomoRemaining % 60).padStart(2, '0');
    const pomoPct = pomoTotal > 0 ? ((pomoTotal - pomoRemaining) / pomoTotal) * 100 : 0;
    if (s.isGameRunning && !pomoRunning) {
      document.getElementById('mh-timer-label').textContent = '⏱️ 플레이타임';
      document.getElementById('mh-timer-state').textContent = 'LIVE 🔴';
      document.getElementById('mh-timer-val').textContent = s.activeRunHMS;
      document.getElementById('mh-timer-bar').style.width = '100%';
      document.getElementById('mh-timer-sub').textContent = `🍅 뽀모도로 ${pm}:${ps} (클릭시작)`;
    } else {
      document.getElementById('mh-timer-label').textContent = pomoIsBreak ? '☕ 휴식타이머' : '🍅 집중타이머';
      document.getElementById('mh-timer-state').textContent = pomoRunning ? '진행 중 🔥' : '일시정지';
      document.getElementById('mh-timer-val').textContent = `${pm}:${ps}`;
      document.getElementById('mh-timer-bar').style.width = `${pomoPct.toFixed(1)}%`;
      document.getElementById('mh-timer-sub').textContent = s.isGameRunning ? `🎮 ${s.activeRunHMS}` : '클릭하여 시작/정지';
    }
  }

  let currentStartupEnabled = false;

  function updateStartupSwitchUI(enabled) {
    currentStartupEnabled = Boolean(enabled);
    const pill = document.getElementById('startup-switch-pill');
    if (!pill) return;
    pill.textContent = currentStartupEnabled ? 'ON' : 'OFF';
    pill.classList.toggle('on', currentStartupEnabled);
  }

  async function toggleStartupAutoRun() {
    const nextState = !currentStartupEnabled;
    try {
      const res = await apiFetch(`/api/startup?enable=${nextState ? '1' : '0'}`, { method: 'POST' });
      const data = await res.json();
      updateStartupSwitchUI(data.enabled);
      if (data.enabled) {
        showToast('🚀 윈도우 시작 시 자동 실행이 활성화(ON)되었습니다.');
      } else {
        showToast('⏹️ 윈도우 시작 시 자동 실행이 해제(OFF)되었습니다.');
      }
    } catch (e) {
      showToast('⚠️ 시작프로그램 설정 변경 중 오류가 발생했습니다.');
    }
  }

  async function onUploadCustomAvatar(event) {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    try {
      const buf = await file.arrayBuffer();
      const res = await apiFetch('/api/avatar', {
        method: 'POST',
        body: buf
      });
      const data = await res.json();
      if (data.ok) {
        document.getElementById('user-avatar-img').src = '/api/avatar?t=' + Date.now();
        showToast('📷 프로필 사진이 변경되었습니다.');
      } else {
        showToast('⚠️ 프로필 사진 저장에 실패했습니다.');
      }
    } catch (e) {
      showToast('⚠️ 프로필 사진 업로드 중 오류가 발생했습니다.');
    }
    event.target.value = '';
  }

  async function resetCustomAvatar(event) {
    event.preventDefault();
    event.stopPropagation();
    try {
      await apiFetch('/api/avatar?reset=1', { method: 'POST' });
      document.getElementById('user-avatar-img').src = '/api/avatar?t=' + Date.now();
      showToast('🔄 Windows 기본 계정 프로필 사진으로 복원했습니다.');
    } catch (e) {
      console.error(e);
    }
  }

  function showErrorFallbackOverlay(msg) {
    const box = document.getElementById('error-fallback-detail-box');
    if (box && msg) {
      box.textContent = msg;
    }
    const overlay = document.getElementById('error-fallback-overlay');
    if (overlay) {
      overlay.classList.remove('hidden');
    }
  }

  function hideErrorFallbackOverlay() {
    const overlay = document.getElementById('error-fallback-overlay');
    if (overlay && !overlay.classList.contains('hidden')) {
      overlay.classList.add('hidden');
    }
  }

  async function retryConnectionNow() {
    const btn = document.getElementById('btn-retry-conn');
    if (btn) btn.textContent = '연결 시도 중...';
    statsFailCount = 0;
    try {
      await fetchStats();
      showToast('✅ 연결 복구에 성공했습니다.');
    } catch (e) {
      showToast('❌ 아직 연결되지 않았습니다. 프로그램 재시작을 권장합니다.');
    } finally {
      if (btn) btn.textContent = '⚡ 다시 연결 시도';
    }
  }

  async function restartCoreFlowApp() {
    const btn = document.getElementById('btn-restart-app');
    const box = document.getElementById('error-fallback-detail-box');
    if (btn) {
      btn.disabled = true;
      btn.textContent = '🔄 새 창 실행 중...';
    }
    if (box) {
      box.textContent = '새로운 CoreFlow 창을 실행하고 있습니다. 이전 창은 잠시 후 자동으로 닫힙니다...';
    }
    try {
      await apiFetch('/api/restart_app', { method: 'POST' });
    } catch (e) {
      console.warn('Backend offline, closing window...', e);
    }
    setTimeout(() => {
      window.open('', '_self').close();
      window.close();
    }, 800);
  }

  function openHelpFromError() {
    hideErrorFallbackOverlay();
    openHelpModal();
  }

  let statsInFlight = false;
  let statsInFlightSince = 0;
  let statsFailCount = 0;

  async function fetchStats() {
    // 이전 요청이 아직 처리 중이면 요청이 쌓이지 않도록 건너뜀 (8초 넘게 걸리면 강제 해제)
    if (statsInFlight && Date.now() - statsInFlightSince < 8000) return;
    statsInFlight = true;
    statsInFlightSince = Date.now();
    const ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const abortTimer = ctrl ? setTimeout(() => ctrl.abort(), 6000) : null;
    try {
      const res = await apiFetch('/api/stats?' + getWindowBoundsQuery(), ctrl ? { signal: ctrl.signal } : {});
      const d = await res.json();
      if (statsFailCount >= 3) showToast('✅ 모니터링 서버와 다시 연결되었습니다.');
      statsFailCount = 0;
      hideErrorFallbackOverlay();

      // 0. Windows 테마, 사용자 이름, 시작프로그램 상태 적용
      const applied = applyWindowsTheme(d.theme);
      const accentHex = applied.accent;
      const accentRgb = applied.accentRgb;

      if (d.user_name) {
        document.getElementById('sidebar-user-name').textContent = d.user_name;
      }
      if (typeof d.startup_enabled === 'boolean') {
        updateStartupSwitchUI(d.startup_enabled);
      }

      // 1. CPU 업데이트
      const cpuTempC = typeof d.cpu_temp_c === 'number' && d.cpu_temp_c > 0 ? d.cpu_temp_c : null;
      const cpuPctText = `${d.cpu.toFixed(1)}%`;
      if (cpuTempC !== null) {
        const cpuTempColor = cpuTempC >= 80 ? 'var(--red)' : (cpuTempC >= 70 ? 'var(--yellow)' : 'var(--neon-green)');
        document.getElementById('cpu-percent').innerHTML = `${cpuPctText} <span style="font-size:0.75em; opacity:0.88; font-weight:700; margin-left:3px; color:${cpuTempColor}">/ ${cpuTempC.toFixed(0)}°C</span>`;
      } else {
        document.getElementById('cpu-percent').innerHTML = `${cpuPctText} <span style="font-size:0.72em; opacity:0.45; font-weight:600; margin-left:3px;">/ -</span>`;
      }
      document.getElementById('cpu-bar').style.width = `${Math.min(100, d.cpu)}%`;
      document.getElementById('core-count-label').textContent = `${d.cores.length} 코어`;
      document.getElementById('sidebar-cpu-brand').textContent = d.cpu_brand;

      const hrs = Math.floor(d.uptime / 3600);
      const mins = Math.floor((d.uptime % 3600) / 60);
      document.getElementById('sidebar-uptime').textContent = `가동 시간: ${hrs}시간 ${mins}분`;

      cpuHistory.push(d.cpu);
      if (cpuHistory.length > 60) cpuHistory.shift();
      drawChart('cpu-canvas', cpuHistory, 100, accentHex, `rgba(${accentRgb}, 0.18)`);

      // 2. RAM 업데이트
      const usedGb = d.used_mem / 1073741824;
      const totalGb = Math.max(0.1, d.total_mem / 1073741824);
      const memPct = (usedGb / totalGb) * 100;
      const swapGb = d.used_swap / 1073741824;

      document.getElementById('mem-percent').textContent = `${memPct.toFixed(1)}%`;
      document.getElementById('mem-detail').textContent = `${usedGb.toFixed(1)} / ${totalGb.toFixed(1)} GB`;
      document.getElementById('mem-bar').style.width = `${Math.min(100, memPct)}%`;
      document.getElementById('swap-label').textContent = `Swap: ${swapGb.toFixed(1)} GB`;

      memHistory.push(memPct);
      if (memHistory.length > 60) memHistory.shift();
      drawChart('mem-canvas', memHistory, 100, '#8e44ad', 'rgba(142, 68, 173, 0.16)');

      // 3. GPU (NVIDIA, AMD Radeon, Intel Arc) 업데이트
      const g = d.gpu || {};
      const gpuUsage = g.usage || 0;
      const vramUsedGb = (g.vram_used_mb || 0) / 1024;
      const vramTotalGb = Math.max(0.1, (g.vram_total_mb || 1024) / 1024);
      const vramPct = ((g.vram_used_mb || 0) / Math.max(1, g.vram_total_mb || 1)) * 100;
      const tempC = g.temp_c || 0;

      document.getElementById('sidebar-gpu-name').textContent = g.name || 'GPU';
      const gpuPctText = `${gpuUsage.toFixed(1)}%`;
      if (tempC > 0) {
        const gpuTempColor = tempC >= 78 ? 'var(--red)' : (tempC >= 65 ? 'var(--yellow)' : 'var(--neon-green)');
        document.getElementById('gpu-percent').innerHTML = `${gpuPctText} <span style="font-size:0.75em; opacity:0.88; font-weight:700; margin-left:3px; color:${gpuTempColor}">/ ${tempC.toFixed(0)}°C</span>`;
      } else {
        document.getElementById('gpu-percent').innerHTML = `${gpuPctText} <span style="font-size:0.72em; opacity:0.45; font-weight:600; margin-left:3px;">/ -</span>`;
      }
      document.getElementById('gpu-vram-detail').textContent = `VRAM ${vramUsedGb.toFixed(2)} / ${vramTotalGb.toFixed(1)} GB`;
      document.getElementById('gpu-bar').style.width = `${Math.min(100, gpuUsage)}%`;

      const tempEl = document.getElementById('gpu-temp-badge');
      if (tempEl) {
        tempEl.textContent = tempC > 0 ? `${tempC.toFixed(0)}°C` : '-';
        tempEl.style.color = tempC >= 78 ? 'var(--red)' : (tempC >= 65 ? 'var(--yellow)' : 'var(--neon-green)');
      }

      document.getElementById('gpu-power-pill').textContent = `⚡ ${(g.power_w || 0).toFixed(1)} W`;
      document.getElementById('gpu-clock-pill').textContent = `⏱️ ${g.clock_mhz || 0} MHz`;
      document.getElementById('gpu-vram-pct-pill').textContent = `VRAM ${vramPct.toFixed(0)}%`;
      document.getElementById('mini-status').textContent = `CPU ${d.cpu.toFixed(0)}%${cpuTempC ? ` (${cpuTempC.toFixed(0)}°C)` : ''} • GPU ${gpuUsage.toFixed(0)}%${tempC > 0 ? ` (${tempC.toFixed(0)}°C)` : ''}`;

      gpuHistory.push(gpuUsage);
      if (gpuHistory.length > 60) gpuHistory.shift();
      gpuTempHistory.push(tempC);
      if (gpuTempHistory.length > 60) gpuTempHistory.shift();
      drawChart('gpu-canvas', gpuHistory, 100, '#e66700', 'rgba(230, 103, 0, 0.18)');

      // 4. 게임 실시간 FPS (Windows 범용 DXGI·D3D9 ETW 하드웨어 측정: NVIDIA/AMD/Intel 지원) 및 실행 시간 업데이트
      const gm = d.game || {};
      latestGameLogs = d.game_logs || [];
      let activeFps = 0;
      let activeMs = 0.0;
      let backendLow1 = 0;
      let targetLabel = '실행 중인 게임 없음';
      let isGameRunning = false;
      let activeRunSecs = 0;

      if (gm.active) {
        targetLabel = gm.name;
        const hwFps = Number(gm.fps || 0);
        const hwMs = Number(gm.frame_ms || 0);
        const hwLow1 = Number(gm.low_1pct_fps || 0);
        activeFps = Math.round(hwFps);
        activeMs = hwMs > 0 ? hwMs : (activeFps > 0 ? (1000.0 / activeFps) : 0.0);
        backendLow1 = Math.round(hwLow1);
        isGameRunning = true;
        activeRunSecs = Number(gm.run_secs || 0);
      } else if (selectedTargetProc !== 'auto') {
        const found = (d.processes || []).find(p => p.name === selectedTargetProc);
        if (found) {
          targetLabel = found.name;
          activeFps = 0;
          activeMs = 0.0;
          isGameRunning = true;
          activeRunSecs = Number(found.run_secs || 0);
        }
      }

      const activeRunHMS = isGameRunning ? formatHMS(activeRunSecs) : '00:00:00';

      fpsHistory.push(activeFps);
      if (fpsHistory.length > 60) fpsHistory.shift();
      frameMsHistory.push(isGameRunning ? activeMs : 0);
      if (frameMsHistory.length > 60) frameMsHistory.shift();

      const validFps = fpsHistory.filter(v => v > 0);
      const sortedFps = [...validFps].sort((a, b) => a - b);
      const low1Pct = isGameRunning
        ? (backendLow1 > 0 ? backendLow1 : (sortedFps.length > 0 ? sortedFps[0] : activeFps))
        : 0;
      const maxFpsScale = Math.max(120, ...validFps);

      document.getElementById('fps-value').textContent = isGameRunning ? `${activeFps} FPS` : `0 FPS`;
      document.getElementById('fps-frametime').textContent = isGameRunning ? `${activeMs.toFixed(1)} ms` : `대기 중`;
      document.getElementById('fps-bar').style.width = isGameRunning ? `${Math.min(100, (activeFps / 165) * 100)}%` : `0%`;
      document.getElementById('fps-low-pill').textContent = `1% Low: ${low1Pct} FPS`;
      const playtimePill = document.getElementById('fps-playtime-pill');
      if (playtimePill) {
        playtimePill.textContent = `⏱️ ${activeRunHMS}`;
        playtimePill.style.color = isGameRunning ? 'var(--neon-green)' : 'var(--text-muted)';
      }
      document.getElementById('fps-target-name').textContent = targetLabel;

      const badgeEl = document.getElementById('fps-mode-badge');
      badgeEl.textContent = isGameRunning ? `LIVE 🔴 ${activeRunHMS}` : 'IDLE';
      badgeEl.style.color = isGameRunning ? 'var(--neon-green)' : 'var(--text-muted)';

      document.getElementById('sidebar-game-header').textContent = isGameRunning ? '🎮 PLAYING A GAME' : '🎮 GAME MONITOR';
      document.getElementById('sidebar-game-name').textContent = isGameRunning ? targetLabel : '실행 중인 게임 없음';
      const sideFpsEl = document.getElementById('sidebar-game-fps');
      sideFpsEl.textContent = isGameRunning
        ? `실시간 ${activeFps} FPS (${activeMs.toFixed(1)} ms)`
        : '게임 실행 시 실시간 FPS가 표시됩니다';
      sideFpsEl.style.color = isGameRunning ? 'var(--neon-green)' : 'var(--text-muted)';

      const sideTimeEl = document.getElementById('sidebar-game-time');
      if (sideTimeEl) {
        sideTimeEl.textContent = isGameRunning
          ? `⏱️ 실행 시간: ${activeRunHMS}`
          : (latestGameLogs.length > 0 ? `최근 기록: ${latestGameLogs[0].name} (${formatHMS(latestGameLogs[0].duration_secs)})` : '⏱️ 실행 시간: 00:00:00');
        sideTimeEl.style.color = isGameRunning ? 'var(--brand)' : 'var(--text-muted)';
      }

      drawChart('fps-canvas', fpsHistory, maxFpsScale, '#00c875', 'rgba(0, 200, 117, 0.16)');

      // 5. 코어별 상세
      const coresEl = document.getElementById('cores-container');
      coresEl.innerHTML = d.cores.map((c, idx) => `
        <div class="core-chip">
          <div class="core-chip-top">
            <span>Core #${idx}</span>
            <strong style="color: var(--text-normal)">${c.toFixed(0)}%</strong>
          </div>
          <div class="progress-track" style="height: 6px;">
            <div class="progress-fill" style="width: ${Math.min(100, c)}%; background-color: ${c > 75 ? 'var(--red)' : 'var(--brand)'};"></div>
          </div>
        </div>
      `).join('');

      const prevLen = latestProcesses.length;
      latestProcesses = d.processes || [];
      if (prevLen === 0 || Math.random() < 0.2) {
        updateProcessDropdown();
      }
      renderProcesses();

      // 5.5 네트워크(다운로드/업로드/핑) & 디스크(용량/I/O) 히스토리 및 요약 바 업데이트
      const net = d.net || {};
      const diskIo = d.disk_io || {};
      const disks = d.disks || [];
      const rxMbs = Number(net.rx_mb_s || 0);
      const txMbs = Number(net.tx_mb_s || 0);
      const rxMbps = Number(net.rx_mbps || 0);
      const txMbps = Number(net.tx_mbps || 0);
      const pingMs = Number(net.ping_ms || 0);
      const jitterMs = Number(net.jitter_ms || 0);
      const diskReadMbs = Number(diskIo.read_mb_s || 0);
      const diskWriteMbs = Number(diskIo.write_mb_s || 0);
      const diskTotalIoMbs = diskReadMbs + diskWriteMbs;

      peakNetRxMbs = Math.max(peakNetRxMbs, rxMbs);
      peakNetTxMbs = Math.max(peakNetTxMbs, txMbs);

      netRxHistory.push(rxMbs);
      if (netRxHistory.length > 60) netRxHistory.shift();
      netTxHistory.push(txMbs);
      if (netTxHistory.length > 60) netTxHistory.shift();
      pingHistory.push(pingMs);
      if (pingHistory.length > 60) pingHistory.shift();
      diskIoHistory.push(diskTotalIoMbs);
      if (diskIoHistory.length > 60) diskIoHistory.shift();

      const stripDown = document.getElementById('strip-net-down');
      if (stripDown) {
        stripDown.textContent = `↓ ${rxMbs.toFixed(2)} MB/s (${rxMbps.toFixed(1)} Mbps)`;
        document.getElementById('strip-net-up').textContent = `↑ ${txMbs.toFixed(2)} MB/s (${txMbps.toFixed(1)} Mbps)`;
        const pingTxt = net.online === false
          ? '오프라인 ⚠️'
          : (net.is_game_ping
            ? `${net.ping_target || '게임 서버'} • ${pingMs.toFixed(1)} ms`
            : `Ping ${pingMs.toFixed(1)} ms (Jitter ${jitterMs.toFixed(1)}ms)`);
        document.getElementById('strip-net-ping').textContent = pingTxt;
        const pingWrap = document.getElementById('strip-ping-wrap');
        if (pingWrap) {
          pingWrap.style.color = net.online === false || pingMs >= 80
            ? 'var(--red)'
            : (pingMs >= 40 ? 'var(--yellow)' : 'var(--neon-green)');
        }
        document.getElementById('strip-disk-io').textContent = `디스크 R ${diskReadMbs.toFixed(2)} / W ${diskWriteMbs.toFixed(2)} MB/s`;
        if (disks.length > 0) {
          document.getElementById('strip-disk-summary').textContent = disks
            .map(dk => `${dk.mount} ${Number(dk.used_pct).toFixed(0)}% (${Number(dk.avail_gb).toFixed(0)}GB 여유)`)
            .join(' • ');
        }
      }

      lastStatsData = {
        raw: d,
        accentHex,
        accentRgb,
        usedGb,
        totalGb,
        memPct,
        swapGb,
        gpuUsage,
        vramUsedGb,
        vramTotalGb,
        vramPct,
        tempC,
        activeFps,
        activeMs,
        low1Pct,
        maxFpsScale,
        targetLabel,
        isGameRunning,
        activeRunSecs,
        activeRunHMS
      };

      updateGridMetricsUI(lastStatsData);

      if (activeMainTab === 'gamelog') {
        renderGameLogDashboard();
      } else if (activeMainTab === 'netdisk') {
        renderNetDiskDashboard();
      }

      // 6. 녹화 중일 경우 실시간 샘플 저장
      if (isRecording) {
        const now = new Date();
        const timeStr = now.toTimeString().split(' ')[0];
        const elapsedSec = Math.max(0, Math.round((now - recordStartTime) / 1000));
        const maxCore = (d.cores && d.cores.length) ? Math.max(...d.cores) : d.cpu;
        const sortedCpu = [...latestProcesses].sort((a, b) => b.cpu - a.cpu);
        const sortedMem = [...latestProcesses].sort((a, b) => b.mem_mb - a.mem_mb);
        const topCpuProc = sortedCpu.length ? `${sortedCpu[0].name} (${sortedCpu[0].cpu.toFixed(1)}%)` : '-';
        const topMemProc = sortedMem.length ? `${sortedMem[0].name} (${sortedMem[0].mem_mb.toFixed(0)}MB)` : '-';

        recordedSamples.push({
          timeStr,
          elapsedSec,
          cpu: Number(d.cpu.toFixed(1)),
          maxCore: Number(maxCore.toFixed(1)),
          memPct: Number(memPct.toFixed(1)),
          usedGb: Number(usedGb.toFixed(2)),
          gpuUsage: Number(gpuUsage.toFixed(1)),
          vramUsedGb: Number(vramUsedGb.toFixed(2)),
          tempC: Number(tempC.toFixed(0)),
          powerW: Number((g.power_w || 0).toFixed(1)),
          clockMhz: Number(g.clock_mhz || 0),
          fps: isGameRunning ? activeFps : 0,
          frameMs: isGameRunning ? Number(activeMs.toFixed(2)) : 0,
          targetGame: isGameRunning ? targetLabel : 'IDLE',
          topCpuProc,
          topMemProc
        });
        updateRecordingButtonsUI();
        const recOverlay = document.getElementById('record-overlay');
        if (recOverlay && !recOverlay.classList.contains('hidden')) {
          renderRecordAnalysis();
        }
      }

      if (activeDetailType) {
        renderDetailView();
      }
      if (isMiniHudMode) {
        renderMiniHud();
      }

      // 7. 과열·과부하 및 장시간 플레이 스마트 경고 평가
      evaluateSmartAlerts(d, memPct, usedGb, totalGb, vramPct, vramUsedGb, vramTotalGb, tempC, isGameRunning, targetLabel, activeRunSecs);
    } catch (e) {
      console.error(e);
      statsFailCount++;
      if (statsFailCount === 3) {
        showToast('⏳ 모니터링 서버 응답 지연 — 자동 복구를 시도하는 중입니다...');
      } else if (statsFailCount >= 5) {
        const errMsg = (e && e.message) ? e.message : '응답 대기 시간 초과 (Connection Timeout)';
        showErrorFallbackOverlay('모니터링 백엔드 서버 응답 지연 또는 통신 중단 (' + errMsg + ')');
      }
    } finally {
      if (abortTimer) clearTimeout(abortTimer);
      statsInFlight = false;
    }
  }

  function updateGridMetricsUI(s) {
    if (!s || !s.raw) return;
    const d = s.raw;
    const g = d.gpu || {};

    // 1. CPU Grid
    const cpuAvg = cpuHistory.length ? (cpuHistory.reduce((a, b) => a + b, 0) / cpuHistory.length) : d.cpu;
    const cpuMax = cpuHistory.length ? Math.max(...cpuHistory) : d.cpu;
    const hrs = Math.floor(d.uptime / 3600);
    const mins = Math.floor((d.uptime % 3600) / 60);

    const elCpuAvg = document.getElementById('cpu-grid-avg');
    if (elCpuAvg) elCpuAvg.textContent = `${cpuAvg.toFixed(1)}%`;
    const elCpuMax = document.getElementById('cpu-grid-max');
    if (elCpuMax) elCpuMax.textContent = `${cpuMax.toFixed(1)}%`;
    const elCpuUptime = document.getElementById('cpu-grid-uptime');
    if (elCpuUptime) elCpuUptime.textContent = `${hrs}시간 ${mins}분`;
    const elCpuBrand = document.getElementById('cpu-grid-brand');
    if (elCpuBrand) elCpuBrand.textContent = d.cpu_brand || 'CPU';
    const elCpuCoresSub = document.getElementById('cpu-grid-cores-sub');
    if (elCpuCoresSub) elCpuCoresSub.textContent = `${d.cores.length} 논리 코어`;

    const elCoresChips = document.getElementById('cpu-grid-core-chips');
    if (elCoresChips && currentDashboardViewMode === 'grid') {
      elCoresChips.innerHTML = d.cores.map((c, i) => `
        <div class="core-mini-chip ${c > 75 ? 'high' : ''}">
          <span style="color:var(--text-muted)">#${i}</span>
          <strong>${c.toFixed(0)}%</strong>
        </div>
      `).join('');
    }

    // 2. RAM Grid
    const memAvg = memHistory.length ? (memHistory.reduce((a, b) => a + b, 0) / memHistory.length) : s.memPct;
    const availGb = Math.max(0, s.totalGb - s.usedGb);
    const totalSwapGb = Math.max(0.1, (d.total_swap || 0) / 1073741824);
    const swapPct = (s.swapGb / totalSwapGb) * 100;

    const elMemUsed = document.getElementById('mem-grid-used');
    if (elMemUsed) elMemUsed.textContent = `${s.usedGb.toFixed(2)} GB`;
    const elMemAvail = document.getElementById('mem-grid-avail');
    if (elMemAvail) elMemAvail.textContent = `${availGb.toFixed(2)} GB`;
    const elMemTotal = document.getElementById('mem-grid-total');
    if (elMemTotal) elMemTotal.textContent = `${s.totalGb.toFixed(1)} GB`;
    const elMemAvg = document.getElementById('mem-grid-avg');
    if (elMemAvg) elMemAvg.textContent = `${memAvg.toFixed(1)}%`;
    const elMemSwap = document.getElementById('mem-grid-swap');
    if (elMemSwap) elMemSwap.textContent = `${s.swapGb.toFixed(2)} / ${totalSwapGb.toFixed(1)} GB (${swapPct.toFixed(0)}%)`;
    const elMemSwapBar = document.getElementById('mem-grid-swap-bar');
    if (elMemSwapBar) elMemSwapBar.style.width = `${Math.min(100, swapPct)}%`;

    // 3. GPU Grid
    const gpuAvg = gpuHistory.length ? (gpuHistory.reduce((a, b) => a + b, 0) / gpuHistory.length) : s.gpuUsage;
    const elGpuTemp = document.getElementById('gpu-grid-temp');
    if (elGpuTemp) {
      elGpuTemp.textContent = `${s.tempC.toFixed(0)}°C`;
      elGpuTemp.style.color = s.tempC >= 78 ? 'var(--red)' : (s.tempC >= 65 ? 'var(--yellow)' : 'var(--neon-green)');
    }
    const elGpuPower = document.getElementById('gpu-grid-power');
    if (elGpuPower) elGpuPower.textContent = `${(g.power_w || 0).toFixed(1)} W`;
    const elGpuClock = document.getElementById('gpu-grid-clock');
    if (elGpuClock) elGpuClock.textContent = `${g.clock_mhz || 0} MHz`;
    const elGpuAvg = document.getElementById('gpu-grid-avg');
    if (elGpuAvg) elGpuAvg.textContent = `${gpuAvg.toFixed(1)}%`;
    const elGpuVramText = document.getElementById('gpu-grid-vram-text');
    if (elGpuVramText) elGpuVramText.textContent = `${s.vramUsedGb.toFixed(2)} / ${s.vramTotalGb.toFixed(1)} GB (${s.vramPct.toFixed(0)}%)`;
    const elGpuVramBar = document.getElementById('gpu-grid-vram-bar');
    if (elGpuVramBar) elGpuVramBar.style.width = `${Math.min(100, s.vramPct)}%`;

    // 4. Game / FPS Grid
    const validFps = fpsHistory.filter(v => v > 0);
    const fpsAvg = validFps.length ? Math.round(validFps.reduce((a, b) => a + b, 0) / validFps.length) : (s.isGameRunning ? s.activeFps : 0);
    const fpsMax = validFps.length ? Math.max(...validFps) : (s.isGameRunning ? s.activeFps : 0);

    const elFpsLow = document.getElementById('fps-grid-low');
    if (elFpsLow) elFpsLow.textContent = s.isGameRunning ? `${s.low1Pct} FPS` : '0 FPS';
    const elFpsMs = document.getElementById('fps-grid-ms');
    if (elFpsMs) elFpsMs.textContent = s.isGameRunning ? `${s.activeMs.toFixed(1)} ms` : '대기 중';
    const elFpsAvg = document.getElementById('fps-grid-avg');
    if (elFpsAvg) elFpsAvg.textContent = s.isGameRunning ? `${fpsAvg} FPS` : '0 FPS';
    const elFpsMax = document.getElementById('fps-grid-max');
    if (elFpsMax) elFpsMax.textContent = s.isGameRunning ? `${fpsMax} FPS` : '0 FPS';
    const elFpsPlaytime = document.getElementById('fps-grid-playtime');
    if (elFpsPlaytime) {
      elFpsPlaytime.textContent = `⏱️ ${s.activeRunHMS || '00:00:00'}`;
      elFpsPlaytime.style.color = s.isGameRunning ? 'var(--neon-green)' : 'var(--text-muted)';
    }
    const elFpsGamename = document.getElementById('fps-grid-gamename');
    if (elFpsGamename) {
      elFpsGamename.textContent = s.isGameRunning ? `${s.targetLabel} (실행 중 🔴)` : s.targetLabel;
      elFpsGamename.style.color = s.isGameRunning ? 'var(--text-normal)' : 'var(--text-muted)';
    }

    // 5. Network / Disk Strip Grid View
    const net = d.net || {};
    const diskIo = d.disk_io || {};
    const disks = d.disks || [];
    const rxMbs = Number(net.rx_mb_s || 0);
    const txMbs = Number(net.tx_mb_s || 0);
    const rxMbps = Number(net.rx_mbps || 0);
    const txMbps = Number(net.tx_mbps || 0);
    const pingMs = Number(net.ping_ms || 0);
    const jitterMs = Number(net.jitter_ms || 0);
    const diskReadMbs = Number(diskIo.read_mb_s || 0);
    const diskWriteMbs = Number(diskIo.write_mb_s || 0);

    const elStripDown = document.getElementById('strip-grid-down');
    if (elStripDown) {
      elStripDown.textContent = `${rxMbs.toFixed(2)} MB/s`;
      const downSub = document.getElementById('strip-grid-down-sub');
      if (downSub) downSub.textContent = `${rxMbps.toFixed(1)} Mbps (피크 ${peakNetRxMbs.toFixed(2)}M)`;
      const elStripUp = document.getElementById('strip-grid-up');
      if (elStripUp) elStripUp.textContent = `${txMbs.toFixed(2)} MB/s`;
      const upSub = document.getElementById('strip-grid-up-sub');
      if (upSub) upSub.textContent = `${txMbps.toFixed(1)} Mbps (피크 ${peakNetTxMbs.toFixed(2)}M)`;

      const pingTxt = net.online === false
        ? '오프라인 ⚠️'
        : (net.is_game_ping ? `${pingMs.toFixed(1)} ms` : `${pingMs.toFixed(1)} ms`);
      const elPing = document.getElementById('strip-grid-ping');
      if (elPing) {
        elPing.textContent = pingTxt;
        elPing.style.color = net.online === false || pingMs >= 80 ? 'var(--red)' : (pingMs >= 40 ? 'var(--yellow)' : 'var(--neon-green)');
      }
      const pingSub = document.getElementById('strip-grid-ping-sub');
      if (pingSub) {
        pingSub.textContent = net.is_game_ping
          ? `${net.ping_target || '게임 세션'} (지터: ${jitterMs.toFixed(1)}ms)`
          : `Jitter ${jitterMs.toFixed(1)} ms`;
      }

      const elDiskIo = document.getElementById('strip-grid-disk-io');
      if (elDiskIo) elDiskIo.textContent = `${(diskReadMbs + diskWriteMbs).toFixed(2)} MB/s`;
      const diskSub = document.getElementById('strip-grid-disk-sub');
      if (diskSub) diskSub.textContent = `R ${diskReadMbs.toFixed(2)} / W ${diskWriteMbs.toFixed(2)} MB/s`;

      if (disks.length > 0) {
        const elDrives = document.getElementById('strip-grid-drives');
        if (elDrives) elDrives.textContent = disks.map(dk => `${dk.mount} ${Number(dk.used_pct).toFixed(0)}%`).join(' • ');
        const elDrivesSub = document.getElementById('strip-grid-drives-sub');
        if (elDrivesSub) elDrivesSub.textContent = disks.map(dk => `${dk.mount} ${Number(dk.avail_gb).toFixed(0)}GB 여유`).join(' • ');
      }
    }
  }

  // ==================== 스마트 경고 알림 (과열/과부하/장시간 게임 플레이) ====================
  const DEFAULT_ALERT_CONFIG = {
    soundEnabled: true,
    cooldownSec: 300,
    gpuTempOn: true,
    gpuTempVal: 78,
    ramOn: true,
    ramVal: 90,
    vramOn: true,
    vramVal: 92,
    cpuOn: true,
    cpuVal: 90,
    playtimeOn: true,
    playtimeMins: 120
  };

  const INITIAL_ALERTS_DATA = /*__COREFLOW_INITIAL_ALERTS__*/null;
  let alertConfig = Object.assign(
    {},
    DEFAULT_ALERT_CONFIG,
    (INITIAL_ALERTS_DATA && INITIAL_ALERTS_DATA.config) ? INITIAL_ALERTS_DATA.config : {}
  );
  let alertHistory = (INITIAL_ALERTS_DATA && Array.isArray(INITIAL_ALERTS_DATA.history))
    ? INITIAL_ALERTS_DATA.history
    : [];
  let alertLastFiredMap = {};
  let alertSnoozedUntilMs = 0;
  let cpuHighStreakSecs = 0;

  function persistAlertsToDisk() {
    apiFetch('/api/alerts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ config: alertConfig, history: alertHistory })
    }).catch(() => {});
  }

  function saveAlertConfig() {
    persistAlertsToDisk();
  }

  function saveAlertHistory() {
    if (alertHistory.length > 100) {
      alertHistory = alertHistory.slice(0, 100);
    }
    persistAlertsToDisk();
  }

  function playAlertBeep(isTest = false) {
    if (!isTest && !alertConfig.soundEnabled) return;
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      const now = ctx.currentTime;

      const osc1 = ctx.createOscillator();
      const gain1 = ctx.createGain();
      osc1.type = 'sine';
      osc1.frequency.setValueAtTime(880, now);
      osc1.frequency.setValueAtTime(1174.66, now + 0.14);
      gain1.gain.setValueAtTime(0.14, now);
      gain1.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
      osc1.connect(gain1);
      gain1.connect(ctx.destination);
      osc1.start(now);
      osc1.stop(now + 0.36);
    } catch (e) {
      console.error(e);
    }
  }

  function syncAlertInputsFromConfig() {
    const setChk = (id, v) => { const el = document.getElementById(id); if (el) el.checked = Boolean(v); };
    const setVal = (id, v) => { const el = document.getElementById(id); if (el) el.value = String(v); };
    setChk('alert-sound-chk', alertConfig.soundEnabled);
    setVal('alert-cooldown-sel', alertConfig.cooldownSec || 300);

    setChk('rule-gpu-temp-on', alertConfig.gpuTempOn);
    setVal('rule-gpu-temp-val', alertConfig.gpuTempVal);

    setChk('rule-ram-on', alertConfig.ramOn);
    setVal('rule-ram-val', alertConfig.ramVal);

    setChk('rule-vram-on', alertConfig.vramOn);
    setVal('rule-vram-val', alertConfig.vramVal);

    setChk('rule-cpu-on', alertConfig.cpuOn);
    setVal('rule-cpu-val', alertConfig.cpuVal);

    setChk('rule-playtime-on', alertConfig.playtimeOn);
    setVal('rule-playtime-val', alertConfig.playtimeMins);

    updateAlertRuleLabels();
  }

  function updateAlertRuleLabels() {
    const setTxt = (id, t) => { const el = document.getElementById(id); if (el) el.textContent = t; };
    setTxt('rule-gpu-temp-label', `${alertConfig.gpuTempVal}°C 이상`);
    setTxt('rule-ram-label', `${alertConfig.ramVal}% 이상`);
    setTxt('rule-vram-label', `${alertConfig.vramVal}% 이상`);
    setTxt('rule-cpu-label', `${alertConfig.cpuVal}% 이상`);
    const mins = Number(alertConfig.playtimeMins || 120);
    const hrsTxt = mins >= 60
      ? (mins % 60 === 0 ? `${mins / 60}시간` : `${Math.floor(mins / 60)}시간 ${mins % 60}분`)
      : `${mins}분`;
    setTxt('rule-playtime-label', `${mins}분 (${hrsTxt})`);
  }

  function onUpdateAlertConfig() {
    const getChk = id => Boolean(document.getElementById(id)?.checked);
    const getNum = (id, def) => Number(document.getElementById(id)?.value || def);

    alertConfig.soundEnabled = getChk('alert-sound-chk');
    alertConfig.cooldownSec = getNum('alert-cooldown-sel', 300);

    alertConfig.gpuTempOn = getChk('rule-gpu-temp-on');
    alertConfig.gpuTempVal = getNum('rule-gpu-temp-val', 78);

    alertConfig.ramOn = getChk('rule-ram-on');
    alertConfig.ramVal = getNum('rule-ram-val', 90);

    alertConfig.vramOn = getChk('rule-vram-on');
    alertConfig.vramVal = getNum('rule-vram-val', 92);

    alertConfig.cpuOn = getChk('rule-cpu-on');
    alertConfig.cpuVal = getNum('rule-cpu-val', 90);

    alertConfig.playtimeOn = getChk('rule-playtime-on');
    alertConfig.playtimeMins = getNum('rule-playtime-val', 120);

    updateAlertRuleLabels();
    saveAlertConfig();
  }

  function resetAlertConfig() {
    alertConfig = Object.assign({}, DEFAULT_ALERT_CONFIG);
    alertSnoozedUntilMs = 0;
    alertLastFiredMap = {};
    saveAlertConfig();
    syncAlertInputsFromConfig();
    renderAlertSettingsUI();
    showToast('🔄 스마트 경고 설정을 기본값으로 복원했습니다.');
  }

  function clearAlertHistory() {
    alertHistory = [];
    saveAlertHistory();
    renderAlertSettingsUI();
    showToast('🗑️ 스마트 경고 히스토리 기록을 비웠습니다.');
  }

  function snoozeAlerts() {
    alertSnoozedUntilMs = Date.now() + 5 * 60 * 1000;
    const banner = document.getElementById('live-alert-banner');
    if (banner) banner.classList.add('hidden');
    showToast('🔕 5분간 상단 경고 배너 및 사운드 알림을 일시 숨김 처리했습니다.');
  }

  function openAlertSettings() {
    closeDetailView();
    closeRecordAnalysis();
    closeUiSettingsModal();
    closeHelpModal();
    syncAlertInputsFromConfig();
    renderAlertSettingsUI();
    const overlay = document.getElementById('alert-overlay');
    if (overlay) overlay.classList.remove('hidden');
    ['overview', 'system', 'netdisk', 'gamelog', 'productivity', 'analysis', 'alerts', 'uisettings', 'help'].forEach(t => {
      const ch = document.getElementById('chan-' + t);
      const rl = document.getElementById('rail-' + t);
      if (ch) ch.classList.toggle('active', t === 'alerts');
      if (rl) rl.classList.toggle('active', t === 'alerts');
    });
  }

  function closeAlertSettings() {
    const overlay = document.getElementById('alert-overlay');
    if (overlay && !overlay.classList.contains('hidden')) {
      overlay.classList.add('hidden');
      ['overview', 'system', 'netdisk', 'gamelog', 'productivity', 'analysis', 'alerts', 'uisettings', 'help'].forEach(t => {
        const ch = document.getElementById('chan-' + t);
        const rl = document.getElementById('rail-' + t);
        if (ch) ch.classList.toggle('active', t === activeMainTab);
        if (rl) rl.classList.toggle('active', t === activeMainTab);
      });
    }
  }

  function testSmartAlert() {
    const now = new Date();
    const pad = n => String(n).padStart(2, '0');
    const tsStr = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
    const s = lastStatsData;
    const curTemp = s ? `${s.tempC.toFixed(0)}°C` : '82°C';
    alertHistory.unshift({
      time: tsStr,
      title: '🧪 가상 과열·과부하 테스트 경고',
      detail: `테스트 발동 (현재 GPU ${curTemp} / 기준 ${alertConfig.gpuTempVal}°C)`,
      context: s && s.isGameRunning ? `🎮 ${s.targetLabel}` : '시스템 대기 중 (테스트)'
    });
    saveAlertHistory();
    playAlertBeep(true);
    alertSnoozedUntilMs = 0;

    const banner = document.getElementById('live-alert-banner');
    const titleEl = document.getElementById('live-alert-title');
    const descEl = document.getElementById('live-alert-desc');
    if (banner && titleEl && descEl) {
      titleEl.textContent = '🧪 [테스트 경고] 스마트 과열·과부하 감시 알림이 정상 작동합니다!';
      descEl.textContent = `설정된 임계치(GPU ${alertConfig.gpuTempVal}°C, RAM ${alertConfig.ramVal}%, 플레이 ${alertConfig.playtimeMins}분 등) 도달 시 이 배너와 경고음이 즉시 작동합니다.`;
      banner.classList.remove('hidden');
    }
    renderAlertSettingsUI();
    showToast('🔔 가상 스마트 경고가 발동되었습니다! (상단 배너 및 히스토리 확인)');
  }

  function evaluateSmartAlerts(d, memPct, usedGb, totalGb, vramPct, vramUsedGb, vramTotalGb, tempC, isGameRunning, targetLabel, activeRunSecs) {
    // CPU 연속 고부하 초 카운트
    if (d.cpu >= alertConfig.cpuVal) {
      cpuHighStreakSecs++;
    } else {
      cpuHighStreakSecs = 0;
    }

    const activeWarnings = [];
    if (alertConfig.gpuTempOn && tempC >= alertConfig.gpuTempVal) {
      activeWarnings.push({
        key: 'gpu_temp',
        title: '🌡️ GPU 코어 과열 주의',
        detail: `현재 ${tempC.toFixed(0)}°C (임계치 ${alertConfig.gpuTempVal}°C 초과)`,
        short: `GPU 온도 ${tempC.toFixed(0)}°C (기준 ${alertConfig.gpuTempVal}°C)`
      });
    }
    if (alertConfig.ramOn && memPct >= alertConfig.ramVal) {
      activeWarnings.push({
        key: 'ram_high',
        title: '💾 시스템 RAM 부족 경고',
        detail: `현재 ${memPct.toFixed(1)}% / ${usedGb.toFixed(1)}GB (임계치 ${alertConfig.ramVal}% 초과)`,
        short: `RAM 점유율 ${memPct.toFixed(1)}% (${usedGb.toFixed(1)}/${totalGb.toFixed(1)}GB)`
      });
    }
    if (alertConfig.vramOn && vramPct >= alertConfig.vramVal) {
      activeWarnings.push({
        key: 'vram_high',
        title: '🎛️ 그래픽 VRAM 포화 경고',
        detail: `현재 ${vramPct.toFixed(1)}% / ${vramUsedGb.toFixed(2)}GB (임계치 ${alertConfig.vramVal}% 초과)`,
        short: `VRAM 점유율 ${vramPct.toFixed(0)}% (${vramUsedGb.toFixed(1)}GB)`
      });
    }
    if (alertConfig.cpuOn && cpuHighStreakSecs >= 5) {
      activeWarnings.push({
        key: 'cpu_high',
        title: '⚡ CPU 고부하 지속 경고',
        detail: `현재 ${d.cpu.toFixed(1)}% (${cpuHighStreakSecs}초 연속 ${alertConfig.cpuVal}% 초과)`,
        short: `CPU ${d.cpu.toFixed(1)}% (${cpuHighStreakSecs}초 연속 고부하)`
      });
    }
    const playtimeLimitSecs = Number(alertConfig.playtimeMins || 120) * 60;
    if (alertConfig.playtimeOn && isGameRunning && activeRunSecs >= playtimeLimitSecs) {
      activeWarnings.push({
        key: 'playtime_long',
        title: '⏰ 장시간 게임 플레이 휴식 권고',
        detail: `${targetLabel} 연속 ${formatHMS(activeRunSecs)} 플레이 중 (기준 ${alertConfig.playtimeMins}분 도달)`,
        short: `${targetLabel} 연속 ${formatHMS(activeRunSecs)} 플레이 중 (스트레칭 및 휴식 권장)`
      });
    }

    const nowMs = Date.now();
    const cooldownMs = Math.max(30, Number(alertConfig.cooldownSec || 300)) * 1000;
    const topBtn = document.getElementById('btn-alerts');
    const banner = document.getElementById('live-alert-banner');
    const titleEl = document.getElementById('live-alert-title');
    const descEl = document.getElementById('live-alert-desc');

    if (activeWarnings.length > 0) {
      if (topBtn) {
        topBtn.classList.add('alert-btn-active');
        topBtn.textContent = `🚨 경고 ${activeWarnings.length}건`;
      }

      if (nowMs >= alertSnoozedUntilMs && banner && titleEl && descEl) {
        titleEl.textContent = `🚨 스마트 경고 감지 (${activeWarnings.length}건): ${activeWarnings.map(w => w.title).join(' • ')}`;
        descEl.textContent = activeWarnings.map(w => w.short).join('  |  ');
        banner.classList.remove('hidden');
      }

      // 쿨타임 경과한 경고 항목만 히스토리 기록 및 사운드/토스트 발동
      let newlyTriggered = false;
      const now = new Date();
      const pad = n => String(n).padStart(2, '0');
      const tsStr = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
      const sortedCpu = [...latestProcesses].sort((a, b) => b.cpu - a.cpu);
      const topProcStr = sortedCpu.length ? `${sortedCpu[0].name} (${sortedCpu[0].cpu.toFixed(1)}%)` : '-';
      const ctxStr = isGameRunning ? `🎮 ${targetLabel} (상위: ${topProcStr})` : `상위 부하: ${topProcStr}`;

      activeWarnings.forEach(w => {
        const lastMs = alertLastFiredMap[w.key] || 0;
        if (nowMs - lastMs >= cooldownMs) {
          alertLastFiredMap[w.key] = nowMs;
          newlyTriggered = true;
          alertHistory.unshift({
            time: tsStr,
            title: w.title,
            detail: w.detail,
            context: ctxStr
          });
        }
      });

      if (newlyTriggered) {
        saveAlertHistory();
        if (nowMs >= alertSnoozedUntilMs) {
          playAlertBeep(false);
          showToast(`🚨 ${activeWarnings[0].title}: ${activeWarnings[0].short}`);
        }
      }
    } else {
      if (topBtn) {
        topBtn.classList.remove('alert-btn-active');
        topBtn.textContent = '🔔 스마트 알림';
      }
      if (banner && !titleEl?.textContent.includes('[테스트 경고]')) {
        banner.classList.add('hidden');
      }
    }

    const overlay = document.getElementById('alert-overlay');
    if (overlay && !overlay.classList.contains('hidden')) {
      renderAlertSettingsUI();
    }
  }

  function renderAlertSettingsUI() {
    const s = lastStatsData;
    const setTxt = (id, t) => { const el = document.getElementById(id); if (el) el.textContent = t; };
    if (s) {
      setTxt('live-rule-gpu-temp', `현재 GPU 온도: ${s.tempC.toFixed(0)}°C`);
      setTxt('live-rule-ram', `현재 RAM 점유율: ${s.memPct.toFixed(1)}% (${s.usedGb.toFixed(1)}GB)`);
      setTxt('live-rule-vram', `현재 VRAM 점유율: ${s.vramPct.toFixed(1)}% (${s.vramUsedGb.toFixed(2)}GB)`);
      setTxt('live-rule-cpu', `현재 CPU 사용률: ${s.raw.cpu.toFixed(1)}%`);
      setTxt('live-rule-playtime', s.isGameRunning ? `현재 ${s.targetLabel}: ${s.activeRunHMS}` : '현재 게임 실행: 00:00:00 (대기 중)');
    }

    setTxt('alert-history-count-badge', `${alertHistory.length}건`);
    const tbody = document.getElementById('alert-history-tbody');
    if (!tbody) return;

    if (!alertHistory || alertHistory.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="4" style="text-align:center; padding: 28px 16px; color: var(--text-muted);">
            아직 발생한 과열·과부하 또는 장시간 플레이 경고 내역이 없습니다. (상단 [🧪 가상 경고 발동 테스트] 버튼으로 동작을 미리 확인해 볼 수 있습니다)
          </td>
        </tr>
      `;
    } else {
      tbody.innerHTML = alertHistory.map(item => `
        <tr>
          <td style="font-variant-numeric: tabular-nums; color: var(--text-muted); font-size: 12px; white-space: nowrap;">${escapeHtml(item.time || '-')}</td>
          <td style="font-weight: 800; color: var(--red);">${escapeHtml(item.title || '-')}</td>
          <td style="font-weight: 600; color: var(--text-normal);">${escapeHtml(item.detail || '-')}</td>
          <td style="color: var(--text-muted); font-size: 12px;">${escapeHtml(item.context || '-')}</td>
        </tr>
      `).join('');
    }
  }


  function formatDuration(sec) {
    const m = String(Math.floor(sec / 60)).padStart(2, '0');
    const s = String(sec % 60).padStart(2, '0');
    return `${m}:${s}`;
  }

  function formatFileTimestamp(dt) {
    const y = dt.getFullYear();
    const m = String(dt.getMonth() + 1).padStart(2, '0');
    const d = String(dt.getDate()).padStart(2, '0');
    const hh = String(dt.getHours()).padStart(2, '0');
    const mm = String(dt.getMinutes()).padStart(2, '0');
    const ss = String(dt.getSeconds()).padStart(2, '0');
    return `${y}${m}${d}_${hh}${mm}${ss}`;
  }

  function updateRecordingButtonsUI() {
    const btnTop = document.getElementById('btn-record');
    const txtTop = document.getElementById('btn-record-text');
    const btnModal = document.getElementById('rec-modal-btn');
    const txtModal = document.getElementById('rec-modal-btn-text');

    if (isRecording) {
      const sec = recordStartTime ? Math.max(0, Math.round((new Date() - recordStartTime) / 1000)) : 0;
      const label = `⏹️ 정지 (${formatDuration(sec)})`;
      btnTop.classList.add('recording');
      txtTop.textContent = label;
      if (btnModal) {
        btnModal.classList.add('recording');
        txtModal.textContent = `⏹️ 녹화 정지 (${formatDuration(sec)} • ${recordedSamples.length}샘플)`;
      }
    } else {
      btnTop.classList.remove('recording');
      txtTop.textContent = '녹화 시작';
      if (btnModal) {
        btnModal.classList.remove('recording');
        txtModal.textContent = '새 녹화 시작';
      }
    }
  }

  function csvSafe(val) {
    const s = String(val ?? '');
    if (s.includes(',') || s.includes('"') || s.includes('\n')) {
      return '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
  }

  function buildCsvFromSamples(samples) {
    const headers = [
      '시각(Time)',
      '경과초(Sec)',
      'CPU사용률(%)',
      '최고코어부하(%)',
      'RAM점유율(%)',
      'RAM사용량(GB)',
      'GPU사용률(%)',
      'VRAM사용량(GB)',
      'GPU온도(C)',
      'GPU소비전력(W)',
      'GPU클럭(MHz)',
      '게임FPS',
      '프레임타임(ms)',
      '타겟게임',
      '상위CPU프로세스',
      '상위RAM프로세스'
    ];
    const rows = [headers.join(',')];
    samples.forEach(s => {
      rows.push([
        csvSafe(s.timeStr),
        s.elapsedSec,
        s.cpu,
        s.maxCore,
        s.memPct,
        s.usedGb,
        s.gpuUsage,
        s.vramUsedGb,
        s.tempC,
        s.powerW,
        s.clockMhz,
        s.fps,
        s.frameMs,
        csvSafe(s.targetGame),
        csvSafe(s.topCpuProc),
        csvSafe(s.topMemProc)
      ].join(','));
    });
    return rows.join('\r\n');
  }

  async function toggleRecording() {
    if (!isRecording) {
      isRecording = true;
      recordStartTime = new Date();
      recordEndTime = null;
      recordedSamples = [];
      lastSavedFilePath = '';
      lastSavedFileName = '';
      scrubHoverIndex = -1;
      updateRecordingButtonsUI();
      showToast('🔴 실시간 모니터링 녹화를 시작했습니다. 원하는 시점에 [녹화 정지]를 눌러주세요.');
      // 시작 즉시 첫 샘플 1개 수집
      if (lastStatsData) {
        fetchStats();
      }
    } else {
      isRecording = false;
      recordEndTime = new Date();
      updateRecordingButtonsUI();

      if (recordedSamples.length === 0) {
        showToast('⚠️ 수집된 모니터링 샘플이 없습니다.');
        return;
      }

      const fileName = `monitoring_${formatFileTimestamp(recordStartTime)}.csv`;
      const csvText = buildCsvFromSamples(recordedSamples);
      try {
        const res = await apiFetch(`/api/save_record?name=${encodeURIComponent(fileName)}`, {
          method: 'POST',
          headers: { 'Content-Type': 'text/csv; charset=utf-8' },
          body: csvText
        });
        const data = await res.json();
        if (data.ok) {
          lastSavedFilePath = data.path;
          lastSavedFileName = data.name;
          showToast(`💾 녹화 완료! ${data.path} 에 자동 저장되었습니다.`);
        } else {
          showToast('⚠️ 파일 자동 저장에 실패했지만 분석 리포트는 확인 가능합니다.');
        }
      } catch (e) {
        console.error(e);
      }

      openRecordAnalysis();
    }
  }

  async function openLogsFolder() {
    try {
      await apiFetch('/api/open_logs', { method: 'POST' });
      showToast('📂 Windows 탐색기에서 녹화 저장 폴더(logs)를 열었습니다.');
    } catch (e) {
      showToast('⚠️ 폴더 열기에 실패했습니다.');
    }
  }

  function downloadCurrentCsv() {
    if (!recordedSamples || recordedSamples.length === 0) {
      showToast('⚠️ 다운로드할 녹화 데이터가 없습니다.');
      return;
    }
    const csvText = '\uFEFF' + buildCsvFromSamples(recordedSamples);
    const blob = new Blob([csvText], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = lastSavedFileName || `monitoring_${formatFileTimestamp(new Date())}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('💾 CSV 파일 다운로드를 시작했습니다.');
  }

  function parseCsvLine(line) {
    const out = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (inQuotes) {
        if (ch === '"' && line[i + 1] === '"') {
          cur += '"';
          i++;
        } else if (ch === '"') {
          inQuotes = false;
        } else {
          cur += ch;
        }
      } else {
        if (ch === '"') {
          inQuotes = true;
        } else if (ch === ',') {
          out.push(cur);
          cur = '';
        } else {
          cur += ch;
        }
      }
    }
    out.push(cur);
    return out;
  }

  function onLoadCsvFile(event) {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = e => {
      const text = String(e.target.result || '').replace(/^\uFEFF/, '');
      const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0);
      if (lines.length < 2) {
        showToast('⚠️ 유효한 모니터링 CSV 데이터가 아닙니다.');
        return;
      }
      const loaded = [];
      for (let i = 1; i < lines.length; i++) {
        const cols = parseCsvLine(lines[i]);
        if (cols.length < 13) continue;
        loaded.push({
          timeStr: cols[0] || `Sample #${i}`,
          elapsedSec: parseFloat(cols[1]) || (i - 1),
          cpu: parseFloat(cols[2]) || 0,
          maxCore: parseFloat(cols[3]) || 0,
          memPct: parseFloat(cols[4]) || 0,
          usedGb: parseFloat(cols[5]) || 0,
          gpuUsage: parseFloat(cols[6]) || 0,
          vramUsedGb: parseFloat(cols[7]) || 0,
          tempC: parseFloat(cols[8]) || 0,
          powerW: parseFloat(cols[9]) || 0,
          clockMhz: parseFloat(cols[10]) || 0,
          fps: parseFloat(cols[11]) || 0,
          frameMs: parseFloat(cols[12]) || 0,
          targetGame: cols[13] || 'IDLE',
          topCpuProc: cols[14] || '-',
          topMemProc: cols[15] || '-'
        });
      }
      if (loaded.length === 0) {
        showToast('⚠️ CSV 파일에서 샘플을 읽지 못했습니다.');
        return;
      }
      recordedSamples = loaded;
      lastSavedFileName = file.name;
      lastSavedFilePath = `불러온 파일: ${file.name}`;
      scrubHoverIndex = -1;
      renderRecordAnalysis();
      showToast(`📥 ${file.name} (${loaded.length}개 샘플) 파일을 불러와 분석했습니다.`);
    };
    reader.readAsText(file, 'utf-8');
    event.target.value = '';
  }

  function snapshotRecent60sToRecord() {
    if (!lastStatsData) return;
    const now = new Date();
    recordedSamples = [];
    const len = cpuHistory.length;
    for (let i = 0; i < len; i++) {
      const secAgo = len - 1 - i;
      const t = new Date(now.getTime() - secAgo * 1000);
      recordedSamples.push({
        timeStr: t.toTimeString().split(' ')[0],
        elapsedSec: i,
        cpu: Number((cpuHistory[i] || 0).toFixed(1)),
        maxCore: Number((cpuHistory[i] || 0).toFixed(1)),
        memPct: Number((memHistory[i] || 0).toFixed(1)),
        usedGb: Number(lastStatsData.usedGb.toFixed(2)),
        gpuUsage: Number((gpuHistory[i] || 0).toFixed(1)),
        vramUsedGb: Number(lastStatsData.vramUsedGb.toFixed(2)),
        tempC: Number((gpuTempHistory[i] || lastStatsData.tempC || 0).toFixed(0)),
        powerW: Number(((lastStatsData.raw.gpu && lastStatsData.raw.gpu.power_w) || 0).toFixed(1)),
        clockMhz: Number((lastStatsData.raw.gpu && lastStatsData.raw.gpu.clock_mhz) || 0),
        fps: Number(fpsHistory[i] || 0),
        frameMs: Number((frameMsHistory[i] || 0).toFixed(2)),
        targetGame: lastStatsData.isGameRunning ? lastStatsData.targetLabel : 'IDLE',
        topCpuProc: latestProcesses[0] ? `${latestProcesses[0].name}` : '-',
        topMemProc: latestProcesses[0] ? `${latestProcesses[0].name}` : '-'
      });
    }
    lastSavedFilePath = '최근 60초 실시간 버퍼 스냅샷 (파일 저장 전)';
    lastSavedFileName = `snapshot_60s_${formatFileTimestamp(now)}.csv`;
    renderRecordAnalysis();
    showToast('⚡ 최근 60초 데이터를 즉시 불러와 정밀 분석 리포트를 생성했습니다.');
  }

  function openRecordAnalysis() {
    closeDetailView();
    closeUiSettingsModal();
    closeHelpModal();
    const overlay = document.getElementById('record-overlay');
    overlay.classList.remove('hidden');
    ['overview', 'system', 'netdisk', 'gamelog', 'productivity', 'analysis', 'alerts', 'uisettings', 'help'].forEach(t => {
      const ch = document.getElementById('chan-' + t);
      const rl = document.getElementById('rail-' + t);
      if (ch) ch.classList.toggle('active', t === 'analysis');
      if (rl) rl.classList.toggle('active', t === 'analysis');
    });
    renderRecordAnalysis();
  }

  function closeRecordAnalysis() {
    const overlay = document.getElementById('record-overlay');
    if (overlay) overlay.classList.add('hidden');
    ['overview', 'system', 'netdisk', 'gamelog', 'productivity', 'analysis', 'alerts', 'uisettings', 'help'].forEach(t => {
      const ch = document.getElementById('chan-' + t);
      const rl = document.getElementById('rail-' + t);
      if (ch) ch.classList.toggle('active', t === activeMainTab);
      if (rl) rl.classList.toggle('active', t === activeMainTab);
    });
  }

  function toggleRecSeries(key) {
    recSeriesVisible[key] = !recSeriesVisible[key];
    const pill = document.getElementById('sp-' + key);
    if (pill) pill.classList.toggle('active', recSeriesVisible[key]);
    drawMultiTimelineChart();
  }

  function calcMetricSummary(samples, key, ignoreZero = false) {
    const arr = ignoreZero ? samples.filter(s => s[key] > 0) : samples;
    if (!arr || arr.length === 0) {
      return { avg: 0, max: 0, min: 0, peakTime: '-', low1Pct: 0 };
    }
    let sum = 0;
    let maxVal = -Infinity;
    let minVal = Infinity;
    let peakTime = arr[0].timeStr;
    arr.forEach(s => {
      const v = Number(s[key] || 0);
      sum += v;
      if (v > maxVal) {
        maxVal = v;
        peakTime = `${s.timeStr} (+${s.elapsedSec}s)`;
      }
      if (v < minVal) minVal = v;
    });
    const sorted = arr.map(s => Number(s[key] || 0)).sort((a, b) => a - b);
    const lowIdx = Math.max(0, Math.floor(sorted.length * 0.01));
    return {
      avg: sum / arr.length,
      max: maxVal,
      min: minVal,
      peakTime,
      low1Pct: sorted[lowIdx] || 0
    };
  }

  function getMostFrequentItem(samples, key) {
    const counts = {};
    samples.forEach(s => {
      const raw = String(s[key] || '-').split(' (')[0];
      if (!raw || raw === '-') return;
      counts[raw] = (counts[raw] || 0) + 1;
    });
    let best = '-';
    let bestCnt = 0;
    Object.entries(counts).forEach(([k, c]) => {
      if (c > bestCnt) {
        best = k;
        bestCnt = c;
      }
    });
    return best;
  }

  function renderRecordAnalysis() {
    const subEl = document.getElementById('rec-meta-sub');
    const pathEl = document.getElementById('rec-saved-path-text');
    const badgeEl = document.getElementById('rec-sample-badge');
    const insightGrid = document.getElementById('rec-insight-grid');
    const tbody = document.getElementById('rec-stats-tbody');

    if (!recordedSamples || recordedSamples.length === 0) {
      subEl.textContent = '아직 녹화된 구간 데이터가 없습니다.';
      badgeEl.textContent = '샘플 0개';
      pathEl.innerHTML = `💡 상단 <strong>[모니터링 녹화]</strong> 버튼을 눌러 구간 녹화를 시작하거나, 지금 바로 <button class="btn" style="padding:3px 10px; font-size:11.5px; margin:0 6px;" onclick="snapshotRecent60sToRecord()">⚡ 최근 60초 버퍼 즉시 분석하기</button> 또는 <strong>[📥 CSV 불러오기]</strong>를 눌러보세요!`;
      insightGrid.innerHTML = `
        <div class="insight-card"><span class="insight-title">1️⃣ 구간 녹화 시작</span><span class="insight-body">원하는 시점에 <strong>[모니터링 녹화]</strong>를 누르면 1초 단위로 모든 하드웨어/게임 지표가 기록됩니다.</span></div>
        <div class="insight-card"><span class="insight-title">2️⃣ 정지 시 자동 CSV 저장</span><span class="insight-body"><strong>[녹화 정지]</strong>를 누르면 <code>logs/</code> 폴더에 엑셀 호환 CSV 파일로 자동 저장됩니다.</span></div>
        <div class="insight-card"><span class="insight-title">3️⃣ 자동 병목/발열 진단</span><span class="insight-body">수집된 구간의 CPU·GPU 병목 여부, 최고 온도, 1% Low FPS 방어율을 자동 분석합니다.</span></div>
        <div class="insight-card"><span class="insight-title">4️⃣ 시점별 마우스 스크러빙</span><span class="insight-body">타임라인 그래프 위에 마우스를 움직여 특정 초(Second)의 상태와 주범 프로세스를 추적합니다.</span></div>
      `;
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:24px;">녹화된 데이터가 없습니다. [모니터링 녹화] 후 [정지]를 누르거나 [최근 60초 버퍼 즉시 분석하기]를 눌러주세요.</td></tr>`;
      drawMultiTimelineChart();
      return;
    }

    const first = recordedSamples[0];
    const last = recordedSamples[recordedSamples.length - 1];
    const totalSec = recordedSamples.length;
    subEl.textContent = `녹화 구간: ${first.timeStr} ~ ${last.timeStr} (총 ${totalSec}초 / ${recordedSamples.length}개 샘플) ${isRecording ? '• 🔴 현재 실시간 녹화 진행 중...' : ''}`;
    badgeEl.textContent = `샘플 ${recordedSamples.length}개 (${formatDuration(totalSec)})`;

    if (lastSavedFilePath) {
      pathEl.innerHTML = `✅ <strong>저장 파일:</strong> <code>${escapeHtml(lastSavedFilePath)}</code> &nbsp;•&nbsp; 우측 상단 <strong>[📂 저장 폴더 열기]</strong>로 엑셀(CSV) 원본을 바로 확인할 수 있습니다.`;
    } else if (isRecording) {
      pathEl.innerHTML = `🔴 <strong>실시간 녹화 중...</strong> ([녹화 정지] 버튼을 누르면 <code>logs/</code> 폴더에 CSV 파일로 즉시 저장됩니다)`;
    }

    const cpuSt = calcMetricSummary(recordedSamples, 'cpu');
    const coreSt = calcMetricSummary(recordedSamples, 'maxCore');
    const memSt = calcMetricSummary(recordedSamples, 'memPct');
    const memGbSt = calcMetricSummary(recordedSamples, 'usedGb');
    const gpuSt = calcMetricSummary(recordedSamples, 'gpuUsage');
    const vramSt = calcMetricSummary(recordedSamples, 'vramUsedGb');
    const tempSt = calcMetricSummary(recordedSamples, 'tempC');
    const pwrSt = calcMetricSummary(recordedSamples, 'powerW');
    const fpsSt = calcMetricSummary(recordedSamples, 'fps', true);
    const msSt = calcMetricSummary(recordedSamples, 'frameMs', true);

    const topCpuWinner = getMostFrequentItem(recordedSamples, 'topCpuProc');
    const topMemWinner = getMostFrequentItem(recordedSamples, 'topMemProc');

    // 자동 인사이트 진단 생성
    let bottleneckTitle = '⚖️ 시스템 밸런스 양호';
    let bottleneckColor = 'var(--green)';
    let bottleneckDesc = `구간 평균 CPU ${cpuSt.avg.toFixed(1)}%, GPU ${gpuSt.avg.toFixed(1)}%로 병목 현상 없이 여유롭게 작동했습니다.`;
    if (gpuSt.avg >= 80 && cpuSt.avg < 65) {
      bottleneckTitle = '🎛️ GPU 집중 부하 (그래픽 병목 구간)';
      bottleneckColor = 'var(--orange)';
      bottleneckDesc = `GPU 평균 ${gpuSt.avg.toFixed(1)}% (최고 ${gpuSt.max.toFixed(1)}%)로 그래픽 카드 성능을 최대로 끌어쓰는 구간입니다.`;
    } else if (cpuSt.max >= 85 || coreSt.max >= 92) {
      bottleneckTitle = '⚡ CPU 스파이크 / 단일 코어 포화 감지';
      bottleneckColor = 'var(--red)';
      bottleneckDesc = `최고 코어 부하가 ${coreSt.max.toFixed(1)}% (전체 CPU 최고 ${cpuSt.max.toFixed(1)}%)에 도달하여 순간적인 CPU 병목 가능성이 있습니다.`;
    }

    let thermalColor = tempSt.max >= 80 ? 'var(--red)' : (tempSt.max >= 70 ? 'var(--yellow)' : 'var(--neon-green)');
    let thermalDesc = tempSt.max >= 80
      ? `최고 온도 ${tempSt.max.toFixed(0)}°C로 발열이 높습니다. 쿨링 팬 속도를 점검하세요 (최대 전력 ${pwrSt.max.toFixed(1)}W).`
      : `평균 ${tempSt.avg.toFixed(0)}°C / 최고 ${tempSt.max.toFixed(0)}°C로 스로틀링 걱정 없는 쾌적한 온도입니다 (평균 ${pwrSt.avg.toFixed(1)}W).`;

    let fpsDesc = fpsSt.max > 0
      ? `평균 ${fpsSt.avg.toFixed(0)} FPS, 1% Low ${fpsSt.low1Pct.toFixed(0)} FPS (유지율 ${((fpsSt.low1Pct / Math.max(1, fpsSt.avg)) * 100).toFixed(0)}%). 최대 프레임타임 ${msSt.max.toFixed(1)}ms.`
      : `녹화 구간 동안 감지된 활성 3D 게임이 없거나 대기(IDLE) 상태였습니다.`;

    insightGrid.innerHTML = `
      <div class="insight-card" style="border-left-color: ${bottleneckColor};">
        <span class="insight-title">${bottleneckTitle}</span>
        <span class="insight-body">${bottleneckDesc}</span>
      </div>
      <div class="insight-card" style="border-left-color: ${thermalColor};">
        <span class="insight-title">🌡️ GPU 발열 & 소비 전력 진단</span>
        <span class="insight-body">${thermalDesc}</span>
      </div>
      <div class="insight-card" style="border-left-color: var(--neon-green);">
        <span class="insight-title">🎮 게이밍 프레임 안정성 진단</span>
        <span class="insight-body">${fpsDesc}</span>
      </div>
      <div class="insight-card" style="border-left-color: var(--purple);">
        <span class="insight-title">🔥 구간 내 최다 점유 프로세스</span>
        <span class="insight-body">CPU 최다: <strong>${escapeHtml(topCpuWinner)}</strong><br>RAM 최다: <strong>${escapeHtml(topMemWinner)}</strong></span>
      </div>
    `;

    const rowsData = [
      {
        name: '⚡ CPU 전체 사용률',
        avg: `${cpuSt.avg.toFixed(1)}%`,
        max: `${cpuSt.max.toFixed(1)}%`,
        peak: cpuSt.peakTime,
        min: `${cpuSt.min.toFixed(1)}%`,
        eval: cpuSt.max >= 85 ? '⚠️ 고부하 스파이크 발생' : '✅ 안정적'
      },
      {
        name: '🧩 최고 단일 코어 부하',
        avg: `${coreSt.avg.toFixed(1)}%`,
        max: `${coreSt.max.toFixed(1)}%`,
        peak: coreSt.peakTime,
        min: `${coreSt.min.toFixed(1)}%`,
        eval: coreSt.max >= 90 ? '🔥 특정 코어 집중 부하' : '✅ 여유로움'
      },
      {
        name: '💾 시스템 RAM 점유율',
        avg: `${memSt.avg.toFixed(1)}% (${memGbSt.avg.toFixed(2)} GB)`,
        max: `${memSt.max.toFixed(1)}% (${memGbSt.max.toFixed(2)} GB)`,
        peak: memSt.peakTime,
        min: `${memSt.min.toFixed(1)}%`,
        eval: memSt.max >= 85 ? '⚠️ 메모리 부족 주의' : '✅ 메모리 여유 충분'
      },
      {
        name: '🎛️ GPU 코어 사용률',
        avg: `${gpuSt.avg.toFixed(1)}%`,
        max: `${gpuSt.max.toFixed(1)}%`,
        peak: gpuSt.peakTime,
        min: `${gpuSt.min.toFixed(1)}%`,
        eval: gpuSt.max >= 95 ? '🚀 GPU 풀로드 활용' : '✅ 정상 범위'
      },
      {
        name: '🎞️ GPU VRAM 사용량',
        avg: `${vramSt.avg.toFixed(2)} GB`,
        max: `${vramSt.max.toFixed(2)} GB`,
        peak: vramSt.peakTime,
        min: `${vramSt.min.toFixed(2)} GB`,
        eval: '✅ VRAM 안정적'
      },
      {
        name: '🌡️ GPU 코어 온도',
        avg: `${tempSt.avg.toFixed(1)}°C`,
        max: `${tempSt.max.toFixed(0)}°C`,
        peak: tempSt.peakTime,
        min: `${tempSt.min.toFixed(0)}°C`,
        eval: tempSt.max >= 78 ? '🔥 고온 주의' : '❄️ 쿨링 양호'
      },
      {
        name: '⚡ GPU 소비 전력',
        avg: `${pwrSt.avg.toFixed(1)} W`,
        max: `${pwrSt.max.toFixed(1)} W`,
        peak: pwrSt.peakTime,
        min: `${pwrSt.min.toFixed(1)} W`,
        eval: '⚡ 전력 공급 정상'
      },
      {
        name: '🎮 게임 FPS (프레임타임)',
        avg: fpsSt.max > 0 ? `${fpsSt.avg.toFixed(0)} FPS (${msSt.avg.toFixed(1)} ms)` : 'IDLE',
        max: fpsSt.max > 0 ? `${fpsSt.max.toFixed(0)} FPS` : '0 FPS',
        peak: fpsSt.peakTime,
        min: fpsSt.max > 0 ? `${fpsSt.min.toFixed(0)} FPS (1% Low: ${fpsSt.low1Pct.toFixed(0)})` : '0 FPS',
        eval: fpsSt.max > 0 ? '🎮 프레임 측정됨' : '대기 상태'
      }
    ];

    tbody.innerHTML = rowsData.map(r => `
      <tr>
        <td style="font-weight:700;">${r.name}</td>
        <td style="font-variant-numeric:tabular-nums; font-weight:600;">${r.avg}</td>
        <td style="font-variant-numeric:tabular-nums; color:var(--orange); font-weight:700;">${r.max}</td>
        <td style="font-variant-numeric:tabular-nums; color:var(--text-muted);">${r.peak}</td>
        <td style="font-variant-numeric:tabular-nums;">${r.min}</td>
        <td>${r.eval}</td>
      </tr>
    `).join('');

    drawMultiTimelineChart();
  }

  function drawMultiTimelineChart() {
    const canvas = document.getElementById('rec-timeline-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    const gridColor = getComputedStyle(document.body).getPropertyValue('--grid-line').trim() || 'rgba(128,128,128,0.12)';
    const mutedColor = getComputedStyle(document.body).getPropertyValue('--text-muted').trim() || '#949ba4';
    const accentHex = (lastStatsData && lastStatsData.accentHex) ? lastStatsData.accentHex : '#0078d4';

    const chartLeft = 46;
    const chartW = w - 60;
    const chartTop = 16;
    const chartH = h - 38;

    ctx.strokeStyle = gridColor;
    ctx.lineWidth = 1;
    ctx.font = '600 11px "Segoe UI", sans-serif';
    ctx.fillStyle = mutedColor;

    [0.0, 0.25, 0.5, 0.75, 1.0].forEach(r => {
      const y = chartTop + chartH * r;
      ctx.beginPath();
      ctx.moveTo(chartLeft, y);
      ctx.lineTo(chartLeft + chartW, y);
      ctx.stroke();
      ctx.fillText(`${((1 - r) * 100).toFixed(0)}%`, 6, y + 4);
    });

    if (!recordedSamples || recordedSamples.length === 0) {
      ctx.fillText('녹화된 샘플이 없습니다', w / 2 - 60, h / 2);
      return;
    }

    const n = recordedSamples.length;
    ctx.fillText(recordedSamples[0].timeStr, chartLeft, h - 6);
    if (n > 2) {
      const mid = Math.floor(n / 2);
      ctx.fillText(recordedSamples[mid].timeStr, chartLeft + chartW * 0.5 - 24, h - 6);
    }
    ctx.fillText(recordedSamples[n - 1].timeStr, chartLeft + chartW - 52, h - 6);

    const maxFps = Math.max(120, ...recordedSamples.map(s => s.fps || 0));

    const seriesList = [
      { key: 'cpu', show: recSeriesVisible.cpu, color: accentHex, scale: 100 },
      { key: 'mem', prop: 'memPct', show: recSeriesVisible.mem, color: '#8e44ad', scale: 100 },
      { key: 'gpu', prop: 'gpuUsage', show: recSeriesVisible.gpu, color: '#e66700', scale: 100 },
      { key: 'temp', prop: 'tempC', show: recSeriesVisible.temp, color: '#e53935', scale: 100 },
      { key: 'fps', prop: 'fps', show: recSeriesVisible.fps, color: '#00c875', scale: maxFps }
    ];

    const step = n > 1 ? chartW / (n - 1) : chartW;

    seriesList.forEach(sr => {
      if (!sr.show) return;
      const prop = sr.prop || sr.key;
      ctx.beginPath();
      recordedSamples.forEach((s, idx) => {
        const x = n > 1 ? chartLeft + idx * step : chartLeft + chartW / 2;
        const val = Number(s[prop] || 0);
        const ratio = Math.min(1, Math.max(0, val / sr.scale));
        const y = chartTop + chartH - ratio * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.strokeStyle = sr.color;
      ctx.lineWidth = 2.2;
      ctx.stroke();
    });

    // 마우스 스크러빙 수직 가이드선 표시
    if (scrubHoverIndex >= 0 && scrubHoverIndex < n) {
      const hx = n > 1 ? chartLeft + scrubHoverIndex * step : chartLeft + chartW / 2;
      ctx.beginPath();
      ctx.moveTo(hx, chartTop);
      ctx.lineTo(hx, chartTop + chartH);
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }
  }

  function onScrubTimeline(event) {
    if (!recordedSamples || recordedSamples.length === 0) return;
    const canvas = document.getElementById('rec-timeline-canvas');
    const rect = canvas.getBoundingClientRect();
    const relX = ((event.clientX - rect.left) / rect.width) * canvas.width;
    const chartLeft = 46;
    const chartW = canvas.width - 60;
    const ratio = Math.min(1, Math.max(0, (relX - chartLeft) / chartW));
    const idx = Math.round(ratio * (recordedSamples.length - 1));
    scrubHoverIndex = idx;
    drawMultiTimelineChart();

    const s = recordedSamples[idx];
    if (!s) return;
    const infoEl = document.getElementById('rec-scrub-info');
    infoEl.innerHTML = `
      <span>🕒 <strong>${s.timeStr} (+${s.elapsedSec}초)</strong></span>
      <span>⚡ CPU: <strong style="color:var(--brand)">${s.cpu}%</strong> (코어최고 ${s.maxCore}%)</span>
      <span>💾 RAM: <strong style="color:var(--purple)">${s.memPct}%</strong> (${s.usedGb}GB)</span>
      <span>🎛️ GPU: <strong style="color:var(--orange)">${s.gpuUsage}%</strong> (${s.tempC}°C / ${s.powerW}W)</span>
      <span>🎮 FPS: <strong style="color:var(--neon-green)">${s.fps} FPS</strong> (${s.frameMs}ms)</span>
      <span>🔥 상위 CPU: <strong>${escapeHtml(s.topCpuProc)}</strong></span>
    `;
  }

  function onLeaveTimeline() {
    scrubHoverIndex = -1;
    drawMultiTimelineChart();
  }

  function calcHistoryStats(arr) {
    const valid = arr.filter(v => v > 0);
    if (valid.length === 0) return { avg: 0, max: 0, min: 0 };
    const sum = valid.reduce((a, b) => a + b, 0);
    return {
      avg: sum / valid.length,
      max: Math.max(...valid),
      min: Math.min(...valid)
    };
  }

  function drawLargeChart(canvasId, data, maxVal, unit, strokeColor, fillColor) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    const gridColor = getComputedStyle(document.body).getPropertyValue('--grid-line').trim() || 'rgba(128,128,128,0.12)';
    const mutedColor = getComputedStyle(document.body).getPropertyValue('--text-muted').trim() || '#949ba4';
    const scaleMax = Math.max(10, maxVal);

    ctx.strokeStyle = gridColor;
    ctx.lineWidth = 1;
    ctx.font = '600 11px "Segoe UI", sans-serif';
    ctx.fillStyle = mutedColor;

    [0.0, 0.25, 0.5, 0.75, 1.0].forEach(r => {
      const y = 16 + (h - 36) * r;
      ctx.beginPath();
      ctx.moveTo(46, y);
      ctx.lineTo(w - 10, y);
      ctx.stroke();

      const labelVal = ((1 - r) * scaleMax).toFixed(scaleMax >= 50 ? 0 : 1);
      ctx.fillText(`${labelVal}${unit}`, 4, y + 4);
    });

    // 시간축 레이블 (60초 전 ~ 현재)
    ctx.fillText('-60s', 46, h - 4);
    ctx.fillText('-30s', 46 + (w - 56) * 0.5 - 12, h - 4);
    ctx.fillText('현재 (Now)', w - 68, h - 4);

    if (data.length < 2) return;
    const chartLeft = 46;
    const chartW = w - 56;
    const chartTop = 16;
    const chartH = h - 36;
    const step = chartW / (data.length - 1);

    ctx.beginPath();
    data.forEach((val, i) => {
      const x = chartLeft + i * step;
      const ratio = Math.min(1, Math.max(0, val / scaleMax));
      const y = chartTop + chartH - ratio * chartH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = 2.8;
    ctx.stroke();

    ctx.lineTo(chartLeft + chartW, chartTop + chartH);
    ctx.lineTo(chartLeft, chartTop + chartH);
    ctx.closePath();
    ctx.fillStyle = fillColor;
    ctx.fill();
  }

  function openDetailView(type) {
    closeUpdateModal();
    closeUiSettingsModal();
    closeHelpModal();
    activeDetailType = type;
    const overlay = document.getElementById('detail-overlay');
    overlay.classList.remove('hidden');
    ['cpu', 'mem', 'gpu', 'fps'].forEach(t => {
      const btn = document.getElementById('dt-btn-' + t);
      if (btn) {
        btn.className = (t === type) ? 'btn' : 'btn ghost';
      }
    });
    applyDashboardViewMode();
    renderDetailView();
  }

  function closeDetailView() {
    activeDetailType = null;
    const overlay = document.getElementById('detail-overlay');
    if (overlay) overlay.classList.add('hidden');
  }

  function renderDetailView() {
    if (!activeDetailType || !lastStatsData) return;
    const s = lastStatsData;
    const d = s.raw;
    const g = d.gpu || {};
    const kpiGrid = document.getElementById('detail-kpi-grid');
    const extraPanel = document.getElementById('detail-extra-panel');
    const chartWrap = document.getElementById('detail-chart-wrap');
    const gridPanel = document.getElementById('detail-grid-panel');
    const isGrid = (currentDashboardViewMode === 'grid');

    if (chartWrap) chartWrap.style.display = isGrid ? 'none' : 'block';
    if (gridPanel) gridPanel.style.display = isGrid ? 'flex' : 'none';
    if (extraPanel) extraPanel.style.display = isGrid ? 'none' : 'flex';

    if (activeDetailType === 'cpu') {
      const st = calcHistoryStats(cpuHistory);
      document.getElementById('detail-title').textContent = `⚡ CPU 상세 모니터링 (${d.cpu_brand})`;
      document.getElementById('detail-sub').textContent = `논리 코어 ${d.cores.length}개 • 실시간 60초 부하 추이 및 상위 CPU 프로세스`;
      document.getElementById('detail-chart-title').textContent = 'CPU 전체 사용률 추이 (최근 60초)';
      document.getElementById('detail-chart-scale').textContent = 'Scale: 0 ~ 100%';

      const maxCore = d.cores.length ? Math.max(...d.cores) : 0;
      const maxCoreIdx = d.cores.indexOf(maxCore);
      const hrs = Math.floor(d.uptime / 3600);
      const mins = Math.floor((d.uptime % 3600) / 60);

      kpiGrid.innerHTML = `
        <div class="kpi-box"><span class="kpi-label">현재 사용률</span><span class="kpi-val" style="color:${s.accentHex}">${d.cpu.toFixed(1)}%</span></div>
        <div class="kpi-box"><span class="kpi-label">60초 평균</span><span class="kpi-val">${st.avg.toFixed(1)}%</span></div>
        <div class="kpi-box"><span class="kpi-label">60초 최고(Peak)</span><span class="kpi-val" style="color:var(--orange)">${st.max.toFixed(1)}%</span></div>
        <div class="kpi-box"><span class="kpi-label">60초 최저</span><span class="kpi-val">${st.min.toFixed(1)}%</span></div>
        <div class="kpi-box"><span class="kpi-label">논리 코어 수</span><span class="kpi-val">${d.cores.length} Threads</span></div>
        <div class="kpi-box"><span class="kpi-label">최고 부하 코어</span><span class="kpi-val">Core #${maxCoreIdx} (${maxCore.toFixed(0)}%)</span></div>
      `;

      const topCpuProcs = [...latestProcesses].sort((a, b) => b.cpu - a.cpu).slice(0, 8);

      if (isGrid) {
        gridPanel.innerHTML = `
          <div class="card" style="padding: 12px 14px; flex-shrink: 0;">
            <div class="card-header" style="margin-bottom: 6px;">
              <div class="card-title">🧩 논리 코어별 실시간 부하 정밀 매트릭스 (${d.cores.length} Cores)</div>
              <span class="badge" style="color:var(--brand)">최고 부하: Core #${maxCoreIdx} (${maxCore.toFixed(1)}%)</span>
            </div>
            <div class="detail-subgrid">
              ${d.cores.map((c, idx) => `
                <div class="detail-subgrid-card" style="${c > 75 ? 'border-color:rgba(229,57,53,0.5); background:rgba(229,57,53,0.08);' : ''}">
                  <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-size:11px; font-weight:700; color:var(--text-muted)">Core #${idx}</span>
                    <strong style="font-size:13px; font-variant-numeric:tabular-nums; color:${c > 75 ? 'var(--red)' : 'var(--text-normal)'}">${c.toFixed(1)}%</strong>
                  </div>
                  <div class="progress-track" style="height:6px; margin-top:2px;">
                    <div class="progress-fill" style="width:${Math.min(100, c)}%; background-color:${c > 75 ? 'var(--red)' : s.accentHex};"></div>
                  </div>
                </div>
              `).join('')}
            </div>
          </div>

          <div class="detail-grid-row">
            <div class="card detail-card-auto" style="padding: 14px 16px;">
              <div class="card-header" style="margin-bottom: 8px; flex-shrink: 0;">
                <div class="card-title">⚡ CPU 제원 및 동작 통계</div>
              </div>
              <div class="detail-num-table-wrap">
                <table class="detail-num-table">
                  <tbody>
                    <tr><td>프로세서 모델</td><td><strong>${escapeHtml(d.cpu_brand)}</strong></td></tr>
                    <tr><td>물리 / 논리 코어</td><td><strong>${d.cores.length} 논리 스레드</strong></td></tr>
                    <tr><td>실시간 전체 부하</td><td style="color:${s.accentHex}"><strong>${d.cpu.toFixed(1)}%</strong></td></tr>
                    <tr><td>최근 60초 평균 부하</td><td><strong>${st.avg.toFixed(1)}%</strong></td></tr>
                    <tr><td>최근 60초 최고치 (Peak)</td><td style="color:var(--orange)"><strong>${st.max.toFixed(1)}%</strong></td></tr>
                    <tr><td>최근 60초 최저치 (Min)</td><td><strong>${st.min.toFixed(1)}%</strong></td></tr>
                    <tr><td>최고 부하 코어</td><td><strong>Core #${maxCoreIdx} (${maxCore.toFixed(1)}%)</strong></td></tr>
                    <tr><td>시스템 연속 가동 시간</td><td><strong>${hrs}시간 ${mins}분</strong></td></tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div class="card detail-card-auto" style="padding: 14px 16px;">
              <div class="card-header" style="margin-bottom: 8px; flex-shrink: 0;">
                <div class="card-title">🔥 CPU 상위 점유 프로세스 Top 8</div>
              </div>
              <div class="detail-num-table-wrap">
                <table class="detail-num-table">
                  <thead>
                    <tr>
                      <th>PID</th>
                      <th>프로세스명</th>
                      <th>CPU 부하 (%)</th>
                      <th>메모리 (MB)</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${topCpuProcs.map(p => `
                      <tr>
                        <td style="color:var(--text-muted)">${p.pid}</td>
                        <td style="font-weight:700;"><span class="proc-name-cell">${procIconHtml(p.name, 16)}<span>${escapeHtml(p.name)}</span></span></td>
                        <td style="color:var(--orange); font-weight:800;">${p.cpu.toFixed(1)}%</td>
                        <td>${p.mem_mb.toFixed(0)} MB</td>
                      </tr>
                    `).join('')}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        `;
      } else {
        drawLargeChart('detail-main-canvas', cpuHistory, 100, '%', s.accentHex, `rgba(${s.accentRgb}, 0.22)`);

        extraPanel.innerHTML = `
          <div class="card-head">
            <span class="card-title">🧩 논리 코어별 실시간 부하 (${d.cores.length} Cores)</span>
            <span class="badge">실시간 갱신 중</span>
          </div>
          <div class="cores-grid">
            ${d.cores.map((c, idx) => `
              <div class="core-chip">
                <div class="core-chip-top">
                  <span>Core #${idx}</span>
                  <strong style="color: var(--text-normal)">${c.toFixed(1)}%</strong>
                </div>
                <div class="progress-track" style="height: 8px;">
                  <div class="progress-fill" style="width: ${Math.min(100, c)}%; background-color: ${c > 75 ? 'var(--red)' : s.accentHex};"></div>
                </div>
              </div>
            `).join('')}
          </div>
          <div class="card-head" style="margin-top: 8px;">
            <span class="card-title">🔥 CPU 상위 점유 프로세스 Top 6</span>
          </div>
          <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px;">
            ${topCpuProcs.slice(0, 6).map(p => `
              <div class="core-chip" style="display:flex; justify-content:space-between; align-items:center;">
                <span class="proc-name-cell" style="font-size:12px; font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${procIconHtml(p.name, 15)}<span style="overflow:hidden; text-overflow:ellipsis;">${escapeHtml(p.name)} <small style="color:var(--text-muted)">(${p.pid})</small></span></span>
                <strong style="color:var(--orange); font-size:13px; flex-shrink:0;">${p.cpu.toFixed(1)}%</strong>
              </div>
            `).join('')}
          </div>
        `;
      }
    } else if (activeDetailType === 'mem') {
      const st = calcHistoryStats(memHistory);
      const availGb = Math.max(0, s.totalGb - s.usedGb);
      const swapTotalGb = Math.max(0.1, (d.total_swap || 0) / 1073741824);
      const swapPct = (s.swapGb / swapTotalGb) * 100;
      document.getElementById('detail-title').textContent = `💾 시스템 RAM & 가상 메모리 상세 모니터링`;
      document.getElementById('detail-sub').textContent = `물리 메모리 ${s.totalGb.toFixed(1)} GB • 실시간 점유율 및 상위 메모리 프로세스`;
      document.getElementById('detail-chart-title').textContent = '시스템 RAM 점유율 추이 (최근 60초)';
      document.getElementById('detail-chart-scale').textContent = `Scale: 0 ~ 100% (${s.totalGb.toFixed(1)} GB)`;

      kpiGrid.innerHTML = `
        <div class="kpi-box"><span class="kpi-label">현재 점유율</span><span class="kpi-val" style="color:var(--purple)">${s.memPct.toFixed(1)}%</span></div>
        <div class="kpi-box"><span class="kpi-label">사용 중인 RAM</span><span class="kpi-val">${s.usedGb.toFixed(2)} GB</span></div>
        <div class="kpi-box"><span class="kpi-label">가용(여유) RAM</span><span class="kpi-val" style="color:var(--neon-green)">${availGb.toFixed(2)} GB</span></div>
        <div class="kpi-box"><span class="kpi-label">전체 물리 RAM</span><span class="kpi-val">${s.totalGb.toFixed(2)} GB</span></div>
        <div class="kpi-box"><span class="kpi-label">60초 평균 / 최고</span><span class="kpi-val">${st.avg.toFixed(1)}% / ${st.max.toFixed(1)}%</span></div>
        <div class="kpi-box"><span class="kpi-label">Swap 사용량</span><span class="kpi-val">${s.swapGb.toFixed(2)} / ${swapTotalGb.toFixed(1)} GB</span></div>
      `;

      const topMemProcs = [...latestProcesses].sort((a, b) => b.mem_mb - a.mem_mb);

      if (isGrid) {
        gridPanel.innerHTML = `
          <div class="detail-grid-row">
            <div class="card detail-card-auto" style="padding: 14px 16px;">
              <div class="card-header" style="margin-bottom: 8px; flex-shrink: 0;">
                <div class="card-title">💾 시스템 메모리 & 가상 메모리 정밀 통계</div>
              </div>
              <div class="detail-num-table-wrap">
                <table class="detail-num-table">
                  <tbody>
                    <tr><td>물리 RAM 사용량</td><td style="color:var(--purple)"><strong>${s.usedGb.toFixed(2)} GB</strong></td></tr>
                    <tr><td>물리 RAM 가용(여유)</td><td style="color:var(--neon-green)"><strong>${availGb.toFixed(2)} GB</strong></td></tr>
                    <tr><td>전체 물리 RAM 용량</td><td><strong>${s.totalGb.toFixed(2)} GB</strong></td></tr>
                    <tr><td>물리 메모리 점유율</td><td><strong>${s.memPct.toFixed(1)}%</strong></td></tr>
                    <tr><td>60초 평균 / 최고 점유율</td><td><strong>${st.avg.toFixed(1)}% / ${st.max.toFixed(1)}%</strong></td></tr>
                    <tr><td>가상 메모리 (Swap) 사용량</td><td><strong>${s.swapGb.toFixed(2)} GB</strong></td></tr>
                    <tr><td>가상 메모리 총 용량</td><td><strong>${swapTotalGb.toFixed(1)} GB</strong></td></tr>
                    <tr><td>가상 메모리 사용률</td><td><strong>${swapPct.toFixed(0)}%</strong></td></tr>
                    <tr><td>가상 메모리 여유 공간</td><td><strong>${Math.max(0, swapTotalGb - s.swapGb).toFixed(2)} GB</strong></td></tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div class="card detail-card-auto" style="padding: 14px 16px;">
              <div class="card-header" style="margin-bottom: 8px; flex-shrink: 0;">
                <div class="card-title">📊 메모리 점유 상위 프로세스 Top 10</div>
              </div>
              <div class="detail-num-table-wrap">
                <table class="detail-num-table">
                  <thead>
                    <tr>
                      <th>PID</th>
                      <th>프로세스명</th>
                      <th>메모리 사용량</th>
                      <th>물리 RAM 비율</th>
                      <th>CPU</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${topMemProcs.slice(0, 10).map(p => {
                      const pct = Math.min(100, (p.mem_mb / (s.totalGb * 1024)) * 100);
                      return `
                        <tr>
                          <td style="color:var(--text-muted)">${p.pid}</td>
                          <td style="font-weight:700;"><span class="proc-name-cell">${procIconHtml(p.name, 16)}<span>${escapeHtml(p.name)}</span></span></td>
                          <td style="color:var(--purple); font-weight:800;">${p.mem_mb.toFixed(1)} MB</td>
                          <td>${pct.toFixed(1)}%</td>
                          <td>${p.cpu.toFixed(1)}%</td>
                        </tr>
                      `;
                    }).join('')}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        `;
      } else {
        drawLargeChart('detail-main-canvas', memHistory, 100, '%', '#8e44ad', 'rgba(142, 68, 173, 0.22)');

        extraPanel.innerHTML = `
          <div class="card-head">
            <span class="card-title">📊 메모리 점유 상위 프로세스 Top 8</span>
            <span class="badge">물리 RAM 대비 비율</span>
          </div>
          <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px;">
            ${topMemProcs.slice(0, 8).map(p => {
              const pct = Math.min(100, (p.mem_mb / (s.totalGb * 1024)) * 100);
              return `
                <div class="core-chip">
                  <div class="core-chip-top">
                    <span class="proc-name-cell" style="color:var(--text-normal); font-weight:600;">${procIconHtml(p.name, 15)}<span>${escapeHtml(p.name)} <small style="color:var(--text-muted)">(PID: ${p.pid})</small></span></span>
                    <strong style="color:var(--purple); flex-shrink:0;">${p.mem_mb.toFixed(1)} MB (${pct.toFixed(1)}%)</strong>
                  </div>
                  <div class="progress-track" style="height: 7px;">
                    <div class="progress-fill" style="width: ${pct}%; background-color: var(--purple);"></div>
                  </div>
                </div>
              `;
            }).join('')}
          </div>
        `;
      }
    } else if (activeDetailType === 'gpu') {
      const st = calcHistoryStats(gpuHistory);
      const tempSt = calcHistoryStats(gpuTempHistory);
      document.getElementById('detail-title').textContent = `🎛️ GPU 상세 모니터링 (${g.name || 'GPU'})`;
      document.getElementById('detail-sub').textContent = `코어 부하 • VRAM 점유율 • 온도(°C) • 소비 전력(W) • 코어 클럭(MHz)`;
      document.getElementById('detail-chart-title').textContent = 'GPU 코어 사용률 추이 (최근 60초)';
      document.getElementById('detail-chart-scale').textContent = 'Scale: 0 ~ 100%';

      kpiGrid.innerHTML = `
        <div class="kpi-box"><span class="kpi-label">GPU 코어 부하</span><span class="kpi-val" style="color:var(--orange)">${s.gpuUsage.toFixed(1)}%</span></div>
        <div class="kpi-box"><span class="kpi-label">60초 평균 / 최고</span><span class="kpi-val">${st.avg.toFixed(1)}% / ${st.max.toFixed(1)}%</span></div>
        <div class="kpi-box"><span class="kpi-label">VRAM 사용량</span><span class="kpi-val">${s.vramUsedGb.toFixed(2)} / ${s.vramTotalGb.toFixed(1)} GB (${s.vramPct.toFixed(0)}%)</span></div>
        <div class="kpi-box"><span class="kpi-label">GPU 코어 온도</span><span class="kpi-val" style="color:${s.tempC >= 75 ? 'var(--red)' : 'var(--neon-green)'}">${s.tempC.toFixed(0)}°C (최고 ${tempSt.max.toFixed(0)}°C)</span></div>
        <div class="kpi-box"><span class="kpi-label">실시간 소비 전력</span><span class="kpi-val">⚡ ${(g.power_w || 0).toFixed(1)} W</span></div>
        <div class="kpi-box"><span class="kpi-label">그래픽 코어 클럭</span><span class="kpi-val">⏱️ ${g.clock_mhz || 0} MHz</span></div>
      `;

      if (isGrid) {
        gridPanel.innerHTML = `
          <div class="detail-grid-row equal-cols">
            <div class="card detail-card-auto" style="padding: 14px 16px;">
              <div class="card-header" style="margin-bottom: 8px; flex-shrink: 0;">
                <div class="card-title">🎛️ GPU 실시간 센서 및 하드웨어 정밀 수치</div>
              </div>
              <div class="detail-num-table-wrap">
                <table class="detail-num-table">
                  <tbody>
                    <tr><td>그래픽 카드 모델</td><td><strong>${escapeHtml(g.name || 'GPU')}</strong></td></tr>
                    <tr><td>GPU 코어 사용률</td><td style="color:var(--orange)"><strong>${s.gpuUsage.toFixed(1)}%</strong></td></tr>
                    <tr><td>최근 60초 평균 부하</td><td><strong>${st.avg.toFixed(1)}%</strong></td></tr>
                    <tr><td>최근 60초 최고 부하</td><td style="color:var(--orange)"><strong>${st.max.toFixed(1)}%</strong></td></tr>
                    <tr><td>GPU 코어 온도</td><td style="color:${s.tempC >= 78 ? 'var(--red)' : (s.tempC >= 65 ? 'var(--yellow)' : 'var(--neon-green)')}"><strong>${s.tempC.toFixed(0)}°C (최고 ${tempSt.max.toFixed(0)}°C)</strong></td></tr>
                    <tr><td>실시간 소비 전력</td><td><strong>⚡ ${(g.power_w || 0).toFixed(1)} W</strong></td></tr>
                    <tr><td>그래픽 코어 클럭</td><td><strong>⏱️ ${g.clock_mhz || 0} MHz</strong></td></tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div class="card detail-card-auto" style="padding: 14px 16px;">
              <div class="card-header" style="margin-bottom: 8px; flex-shrink: 0;">
                <div class="card-title">🎮 VRAM 비디오 메모리 할당 및 쿨링 상태</div>
              </div>
              <div class="detail-num-table-wrap">
                <table class="detail-num-table">
                  <tbody>
                    <tr><td>전용 VRAM 사용량</td><td style="color:var(--orange)"><strong>${s.vramUsedGb.toFixed(2)} GB (${(g.vram_used_mb || 0).toFixed(0)} MB)</strong></td></tr>
                    <tr><td>전용 VRAM 총 용량</td><td><strong>${s.vramTotalGb.toFixed(1)} GB (${(g.vram_total_mb || 0).toFixed(0)} MB)</strong></td></tr>
                    <tr><td>VRAM 가용(여유) 공간</td><td style="color:var(--neon-green)"><strong>${Math.max(0, s.vramTotalGb - s.vramUsedGb).toFixed(2)} GB</strong></td></tr>
                    <tr><td>VRAM 점유율</td><td><strong>${s.vramPct.toFixed(1)}%</strong></td></tr>
                    <tr><td>온도 상태 평가</td><td style="color:${s.tempC >= 78 ? 'var(--red)' : (s.tempC >= 65 ? 'var(--yellow)' : 'var(--neon-green)')}"><strong>${s.tempC >= 78 ? '🔴 과열 주의 (고온)' : (s.tempC >= 65 ? '🟡 보통' : '🟢 매우 쾌적 (저온)')}</strong></td></tr>
                  </tbody>
                </table>
              </div>
              <div style="margin-top: auto; padding-top: 10px; border-top: 1px dashed var(--border-subtle); flex-shrink: 0;">
                <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom: 4px;">
                  <span style="color:var(--text-muted)">VRAM 할당 게이지</span>
                  <strong>${s.vramPct.toFixed(1)}%</strong>
                </div>
                <div class="progress-track" style="height: 10px;">
                  <div class="progress-fill" style="width: ${Math.min(100, s.vramPct)}%; background-color: var(--orange);"></div>
                </div>
              </div>
            </div>
          </div>
        `;
      } else {
        drawLargeChart('detail-main-canvas', gpuHistory, 100, '%', '#e66700', 'rgba(230, 103, 0, 0.22)');

        extraPanel.innerHTML = `
          <div class="card-head">
            <span class="card-title">🌡️ GPU 온도 추이 (최근 60초, °C) & VRAM 상태</span>
            <span class="badge">현재 ${s.tempC.toFixed(0)}°C</span>
          </div>
          <canvas id="detail-sub-canvas" class="detail-canvas" width="1100" height="150" style="height:150px;"></canvas>
          <div style="display:flex; flex-direction:column; gap:6px; margin-top:4px;">
            <div style="display:flex; justify-content:space-between; font-size:12px; font-weight:600;">
              <span>전용 비디오 메모리 (VRAM) 점유율</span>
              <span>${(g.vram_used_mb || 0).toFixed(0)} MB / ${(g.vram_total_mb || 0).toFixed(0)} MB (${s.vramPct.toFixed(1)}%)</span>
            </div>
            <div class="progress-track" style="height: 10px;">
              <div class="progress-fill" style="width: ${Math.min(100, s.vramPct)}%; background-color: var(--orange);"></div>
            </div>
          </div>
        `;
        drawLargeChart('detail-sub-canvas', gpuTempHistory, 100, '°C', '#e53935', 'rgba(229, 57, 53, 0.16)');
      }
    } else if (activeDetailType === 'fps') {
      const st = calcHistoryStats(fpsHistory);
      const msSt = calcHistoryStats(frameMsHistory);
      document.getElementById('detail-title').textContent = `🎮 게임 FPS & 프레임타임 상세 모니터링`;
      document.getElementById('detail-sub').textContent = `모니터링 대상: ${s.targetLabel} (${s.isGameRunning ? '실행 중 🔴 • 플레이 시간 ' + (s.activeRunHMS || '00:00:00') : '대기 중 IDLE'})`;
      document.getElementById('detail-chart-title').textContent = '실시간 초당 프레임(FPS) 추이 (최근 60초)';
      document.getElementById('detail-chart-scale').textContent = `Scale: 0 ~ ${s.maxFpsScale} FPS`;

      kpiGrid.innerHTML = `
        <div class="kpi-box"><span class="kpi-label">현재 FPS</span><span class="kpi-val" style="color:var(--neon-green)">${s.isGameRunning ? s.activeFps + ' FPS' : '0 FPS'}</span></div>
        <div class="kpi-box"><span class="kpi-label">실행 시간 (시:분:초)</span><span class="kpi-val" style="color:var(--brand); font-variant-numeric:tabular-nums;">⏱️ ${s.activeRunHMS || '00:00:00'}</span></div>
        <div class="kpi-box"><span class="kpi-label">프레임 타임</span><span class="kpi-val">${s.isGameRunning ? s.activeMs.toFixed(2) + ' ms' : '대기 중'}</span></div>
        <div class="kpi-box"><span class="kpi-label">1% Low FPS</span><span class="kpi-val" style="color:var(--yellow)">${s.low1Pct} FPS</span></div>
        <div class="kpi-box"><span class="kpi-label">60초 평균 / 최고 FPS</span><span class="kpi-val">${s.isGameRunning ? st.avg.toFixed(0) + ' / ' + st.max.toFixed(0) : '0'} FPS</span></div>
        <div class="kpi-box"><span class="kpi-label">타겟 프로세스</span><span class="kpi-val" style="font-size:14px;">${escapeHtml(s.targetLabel)}</span></div>
      `;

      if (isGrid) {
        gridPanel.innerHTML = `
          <div class="detail-grid-row equal-cols">
            <div class="card detail-card-auto" style="padding: 14px 16px;">
              <div class="card-header" style="margin-bottom: 8px; flex-shrink: 0;">
                <div class="card-title">🎮 게임 성능 & 프레임타임 정밀 분석</div>
              </div>
              <div class="detail-num-table-wrap">
                <table class="detail-num-table">
                  <tbody>
                    <tr><td>모니터링 대상 게임</td><td style="color:var(--brand)"><strong>${escapeHtml(s.targetLabel)}</strong></td></tr>
                    <tr><td>실시간 게임 세션 시간</td><td style="font-variant-numeric:tabular-nums; color:var(--neon-green)"><strong>⏱️ ${s.activeRunHMS || '00:00:00'}</strong></td></tr>
                    <tr><td>실시간 초당 프레임 (FPS)</td><td style="color:var(--neon-green)"><strong>${s.isGameRunning ? s.activeFps + ' FPS' : '대기 중 (IDLE)'}</strong></td></tr>
                    <tr><td>1% Low FPS</td><td style="color:var(--yellow)"><strong>${s.isGameRunning ? s.low1Pct + ' FPS' : '-'}</strong></td></tr>
                    <tr><td>60초 평균 / 최고 FPS</td><td><strong>${s.isGameRunning ? st.avg.toFixed(0) + ' / ' + st.max.toFixed(0) : '-'} FPS</strong></td></tr>
                    <tr><td>실시간 프레임 타임 (Latency)</td><td><strong>${s.isGameRunning ? s.activeMs.toFixed(2) + ' ms' : '-'}</strong></td></tr>
                    <tr><td>프레임 타임 평균 (Avg Latency)</td><td><strong>${s.isGameRunning ? msSt.avg.toFixed(2) + ' ms' : '-'}</strong></td></tr>
                    <tr><td>프레임 피크 지연 (Peak Latency)</td><td style="color:var(--orange)"><strong>${s.isGameRunning ? msSt.max.toFixed(2) + ' ms' : '-'}</strong></td></tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div class="card detail-card-auto" style="padding: 14px 16px;">
              <div class="card-header" style="margin-bottom: 8px; flex-shrink: 0;">
                <div class="card-title">⏱️ 렌더링 부드러움 지수 및 프레임 안정성</div>
              </div>
              <div class="detail-num-table-wrap">
                <table class="detail-num-table">
                  <tbody>
                    <tr><td>디스플레이 목표 주사율</td><td><strong>60 Hz / 144 Hz</strong></td></tr>
                    <tr><td>60 FPS 기준 목표 타임</td><td><strong>16.67 ms 이내</strong></td></tr>
                    <tr><td>144 FPS 기준 목표 타임</td><td><strong>6.94 ms 이내</strong></td></tr>
                    <tr><td>프레임 안정성 평가</td><td style="font-weight:800; color:${s.isGameRunning ? (s.activeFps >= 60 ? 'var(--neon-green)' : (s.activeFps >= 30 ? 'var(--yellow)' : 'var(--red)')) : 'var(--text-muted)'}">${s.isGameRunning ? (s.activeFps >= 60 ? '🟢 매우 부드러움 (Smooth 60+)' : (s.activeFps >= 30 ? '🟡 보통 (30~60 FPS)' : '🔴 스터터링 발생')) : '대기 중'}</td></tr>
                    <tr><td>1% Low 유지율</td><td style="font-weight:700;">${(s.isGameRunning && s.activeFps > 0) ? ((s.low1Pct / s.activeFps) * 100).toFixed(0) + '%' : '-'}</td></tr>
                  </tbody>
                </table>
              </div>
              <div style="margin-top: auto; padding-top: 10px; border-top: 1px dashed var(--border-subtle); font-size: 12px; color: var(--text-muted); line-height: 1.5; flex-shrink: 0;">
                💡 <strong>1% Low FPS</strong>는 최악의 프레임 하위 1% 순간의 성능을 나타냅니다. 평균 FPS와의 격차가 적을수록 끊김(Stuttering) 없는 부드러운 게이밍 환경을 의미합니다.
              </div>
            </div>
          </div>
        `;
      } else {
        drawLargeChart('detail-main-canvas', fpsHistory, s.maxFpsScale, ' FPS', '#00c875', 'rgba(0, 200, 117, 0.22)');

        extraPanel.innerHTML = `
          <div class="card-head">
            <span class="card-title">⏱️ 프레임 타임 추이 (최근 60초, ms — 낮고 일정할수록 부드러움)</span>
            <span class="badge">${s.isGameRunning ? s.activeMs.toFixed(2) + ' ms' : 'IDLE'}</span>
          </div>
          <canvas id="detail-sub-canvas" class="detail-canvas" width="1100" height="160" style="height:160px;"></canvas>
        `;
        drawLargeChart('detail-sub-canvas', frameMsHistory, 33.3, ' ms', '#0078d4', 'rgba(0, 120, 212, 0.18)');
      }
    }
  }

  // ==================== 도움말 & 이상 징후 가이드 모달 ====================
  function openHelpModal() {
    closeDetailView();
    closeRecordAnalysis();
    closeAlertSettings();
    closeGameScanModal();
    closeUpdateModal();
    closeUiSettingsModal();
    const overlay = document.getElementById('help-overlay');
    if (overlay) overlay.classList.remove('hidden');
    ['overview', 'system', 'netdisk', 'gamelog', 'productivity', 'analysis', 'alerts', 'uisettings', 'help'].forEach(t => {
      const ch = document.getElementById('chan-' + t);
      const rl = document.getElementById('rail-' + t);
      if (ch) ch.classList.toggle('active', t === 'help');
      if (rl) rl.classList.toggle('active', t === 'help');
    });
  }

  function closeHelpModal() {
    const overlay = document.getElementById('help-overlay');
    if (overlay && !overlay.classList.contains('hidden')) {
      overlay.classList.add('hidden');
      ['overview', 'system', 'netdisk', 'gamelog', 'productivity', 'analysis', 'alerts', 'uisettings', 'help'].forEach(t => {
        const ch = document.getElementById('chan-' + t);
        const rl = document.getElementById('rail-' + t);
        if (ch) ch.classList.toggle('active', t === activeMainTab);
        if (rl) rl.classList.toggle('active', t === activeMainTab);
      });
    }
  }

  // ==================== 화면 & 미니 HUD 맞춤 설정 (하드웨어 모니터링 항목 선택 & HUD 모양 설정) ====================
  const DEFAULT_UI_PREFS = {
    dashCpu: true,
    dashRam: true,
    dashGpu: true,
    dashFps: true,
    dashNetDisk: true,
    dashProcs: true,
    dashPomo: true,
    dashProcesses: true,
    dashProductivity: true,
    hudLayoutWide: false,
    hudTopmost: true,
    hudFps: true,
    hudCpu: true,
    hudGpu: true,
    hudRam: true,
    hudNet: true,
    hudTimer: true
  };

  function normalizeUiPrefsObj(obj) {
    const res = Object.assign({}, DEFAULT_UI_PREFS, obj || {});
    if (obj && typeof obj.dashProcs === 'boolean') {
      res.dashProcs = obj.dashProcs;
      res.dashProcesses = obj.dashProcs;
    } else if (obj && typeof obj.dashProcesses === 'boolean') {
      res.dashProcs = obj.dashProcesses;
      res.dashProcesses = obj.dashProcesses;
    }
    if (obj && typeof obj.dashPomo === 'boolean') {
      res.dashPomo = obj.dashPomo;
      res.dashProductivity = obj.dashPomo;
    } else if (obj && typeof obj.dashProductivity === 'boolean') {
      res.dashPomo = obj.dashProductivity;
      res.dashProductivity = obj.dashProductivity;
    }
    return res;
  }

  const INITIAL_UI_PREFS_DATA = /*__COREFLOW_INITIAL_UI_PREFS__*/null;
  let uiPrefs = (function() {
    let localSaved = {};
    try {
      const raw = localStorage.getItem('coreflow_ui_prefs');
      if (raw) localSaved = JSON.parse(raw) || {};
    } catch (e) {}
    return normalizeUiPrefsObj(Object.assign(
      {},
      DEFAULT_UI_PREFS,
      localSaved,
      (INITIAL_UI_PREFS_DATA && typeof INITIAL_UI_PREFS_DATA === 'object') ? INITIAL_UI_PREFS_DATA : {}
    ));
  })();

  function saveUiPrefs() {
    uiPrefs = normalizeUiPrefsObj(uiPrefs);
    try {
      localStorage.setItem('coreflow_ui_prefs', JSON.stringify(uiPrefs));
    } catch (e) {}
    apiFetch('/api/ui_prefs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(uiPrefs)
    }).catch(() => {});
  }

  async function applyUiPrefs(resizeMiniIfActive = false) {
    if (!uiPrefs) return;
    uiPrefs = normalizeUiPrefsObj(uiPrefs);

    // 1. 미니 HUD 레이아웃 형태(박스형 vs 가로바형) 및 항상 위 고정 동기화
    miniHudWideLayout = Boolean(uiPrefs.hudLayoutWide);
    miniHudTopmost = uiPrefs.hudTopmost !== false;
    const mhOverlay = document.getElementById('mini-hud-overlay');
    if (mhOverlay) {
      mhOverlay.classList.toggle('layout-wide', miniHudWideLayout);
    }
    updateMiniHudControlsUI();

    // 2. 메인 대시보드(통합-대시보드 탭일 때) 카드 표시/숨김 및 그리드 자동 확장
    const topCards = [
      { key: 'dashCpu', id: 'card-metric-cpu' },
      { key: 'dashRam', id: 'card-metric-mem' },
      { key: 'dashGpu', id: 'card-metric-gpu' },
      { key: 'dashFps', id: 'card-metric-fps' }
    ];
    let visibleTopCount = 0;
    topCards.forEach(item => {
      const on = uiPrefs[item.key] !== false;
      if (on) visibleTopCount++;
      const el = document.getElementById(item.id);
      if (el && activeMainTab === 'overview') {
        el.classList.toggle('hidden', !on);
      }
    });

    const secMetrics = document.getElementById('sec-metrics');
    if (secMetrics && activeMainTab === 'overview') {
      if (visibleTopCount === 0) {
        secMetrics.classList.add('hidden');
      } else {
        secMetrics.classList.remove('hidden');
        secMetrics.style.gridTemplateColumns = `repeat(${visibleTopCount}, minmax(0, 1fr))`;
      }
    }

    const secNetdiskStrip = document.getElementById('sec-netdisk-strip');
    if (secNetdiskStrip && activeMainTab === 'overview') {
      secNetdiskStrip.classList.toggle('hidden', uiPrefs.dashNetDisk === false);
    }

    const secBottom = document.getElementById('sec-bottom');
    const cardProc = document.getElementById('card-processes');
    const cardProd = document.getElementById('card-productivity');
    const showProc = uiPrefs.dashProcs !== false;
    const showProd = uiPrefs.dashPomo !== false;
    if (activeMainTab === 'overview' && secBottom && cardProc && cardProd) {
      cardProc.classList.toggle('hidden', !showProc);
      cardProd.classList.toggle('hidden', !showProd);
      if (!showProc && !showProd) {
        secBottom.classList.add('hidden');
      } else {
        secBottom.classList.remove('hidden');
        if (showProc && showProd) {
          secBottom.style.gridTemplateColumns = 'minmax(0, 1.35fr) minmax(0, 1fr)';
        } else {
          secBottom.style.gridTemplateColumns = 'minmax(0, 1fr)';
        }
      }
    }

    // 3. 미니 HUD 내부 타일 표시/숨김 및 그리드 칸 수 자동 조절
    const hudTiles = [
      { key: 'hudFps', id: 'mh-tile-fps', label: '🎮 게임 FPS', sample: '144 FPS', color: 'var(--neon-green)' },
      { key: 'hudCpu', id: 'mh-tile-cpu', label: '⚡ CPU 부하', sample: '24.5%', color: 'var(--brand)' },
      { key: 'hudGpu', id: 'mh-tile-gpu', label: '🎛️ GPU·온도', sample: '62% · 61°C', color: 'var(--orange)' },
      { key: 'hudRam', id: 'mh-tile-ram', label: '💾 시스템 RAM', sample: '48.2%', color: 'var(--purple)' },
      { key: 'hudNet', id: 'mh-tile-net', label: '🌐 핑·네트워크', sample: '9.2 ms', color: 'var(--cyan)' },
      { key: 'hudTimer', id: 'mh-tile-timer', label: '⏱️ 플레이타임', sample: '01:24:10', color: 'var(--yellow)' }
    ];
    const activeHudTiles = [];
    hudTiles.forEach(t => {
      const on = uiPrefs[t.key] !== false;
      if (on) activeHudTiles.push(t);
      const tileEl = document.getElementById(t.id);
      if (tileEl) {
        tileEl.classList.toggle('hidden', !on);
      }
    });

    const mhGrid = document.getElementById('mini-hud-grid');
    const targetSize = getMiniHudTargetSize();
    if (mhGrid) {
      mhGrid.style.gridTemplateColumns = `repeat(${targetSize.cols}, minmax(0, 1fr))`;
      mhGrid.style.gridTemplateRows = `repeat(${targetSize.rows}, minmax(0, 1fr))`;
    }

    // 4. 설정 모달 UI 토글 카드 & 배지 상태 동기화
    const allToggleKeys = [
      'dashCpu', 'dashRam', 'dashGpu', 'dashFps', 'dashNetDisk', 'dashProcs', 'dashPomo',
      'hudTopmost', 'hudFps', 'hudCpu', 'hudGpu', 'hudRam', 'hudNet', 'hudTimer'
    ];
    allToggleKeys.forEach(k => {
      const on = uiPrefs[k] !== false;
      const cardEl = document.getElementById('uicard-' + k);
      const pillEl = document.getElementById('uipill-' + k);
      if (cardEl) cardEl.classList.toggle('active', on);
      if (pillEl) {
        pillEl.textContent = on ? 'ON' : 'OFF';
        pillEl.classList.toggle('on', on);
      }
    });

    const dashCount = ['dashCpu', 'dashRam', 'dashGpu', 'dashFps', 'dashNetDisk', 'dashProcs', 'dashPomo']
      .filter(k => uiPrefs[k] !== false).length;
    const dashCountBadge = document.getElementById('ui-dash-count-badge');
    if (dashCountBadge) dashCountBadge.textContent = `${dashCount} / 7개 표시 중`;

    const hudCount = activeHudTiles.length;
    const hudCountBadge = document.getElementById('ui-hud-count-badge');
    if (hudCountBadge) hudCountBadge.textContent = `${hudCount}개 타일 활성`;

    // 5. 컴팩트 박스형 vs 슬림 가로 바형 포커스(.selected) 및 배지 완벽 동기화
    const styleBoxCard = document.getElementById('hudstyle-box');
    const styleBarCard = document.getElementById('hudstyle-bar');
    const styleBoxBadge = document.getElementById('hudstyle-box-badge');
    const styleBarBadge = document.getElementById('hudstyle-bar-badge');
    const previewMeta = document.getElementById('ui-hud-preview-meta');

    if (styleBoxCard) {
      styleBoxCard.classList.toggle('selected', !miniHudWideLayout);
      styleBoxCard.classList.toggle('active', !miniHudWideLayout);
    }
    if (styleBarCard) {
      styleBarCard.classList.toggle('selected', miniHudWideLayout);
      styleBarCard.classList.toggle('active', miniHudWideLayout);
    }
    if (styleBoxBadge) {
      styleBoxBadge.textContent = !miniHudWideLayout ? '선택됨 ✓' : '클릭하여 선택';
      styleBoxBadge.style.background = !miniHudWideLayout ? 'var(--brand)' : '';
      styleBoxBadge.style.color = !miniHudWideLayout ? '#fff' : '';
    }
    if (styleBarBadge) {
      styleBarBadge.textContent = miniHudWideLayout ? '선택됨 ✓' : '클릭하여 선택';
      styleBarBadge.style.background = miniHudWideLayout ? 'var(--brand)' : '';
      styleBarBadge.style.color = miniHudWideLayout ? '#fff' : '';
    }
    if (previewMeta) {
      previewMeta.textContent = miniHudWideLayout
        ? `📏 슬림 가로 바형 (${targetSize.cols}열 × 1줄 · 약 ${targetSize.w}×${targetSize.h}px)`
        : `📦 컴팩트 박스형 (${targetSize.cols}열 × ${targetSize.rows}단 · 약 ${targetSize.w}×${targetSize.h}px)`;
    }

    const previewEl = document.getElementById('ui-hud-live-preview');
    if (previewEl) {
      previewEl.style.gridTemplateColumns = `repeat(${targetSize.cols}, minmax(0, 1fr))`;
      previewEl.innerHTML = activeHudTiles.map(t => `
        <div style="padding: 6px 8px; border-radius: 6px; background: rgba(var(--brand-rgb), 0.10); border: 1px solid rgba(var(--brand-rgb), 0.32); display: flex; flex-direction: column; gap: 2px; min-width: 0;">
          <span style="font-size: 10.5px; font-weight: 700; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${t.label}</span>
          <strong style="font-size: 12px; color: ${t.color}; font-variant-numeric: tabular-nums; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${t.sample}</strong>
        </div>
      `).join('');
    }

    if (resizeMiniIfActive && isMiniHudMode) {
      resizeNativeAppWindow(targetSize.w, targetSize.h);
      try {
        await apiFetch(`/api/window_ctl?topmost=${miniHudTopmost ? '1' : '0'}&w=${targetSize.w}&h=${targetSize.h}`, { method: 'POST' });
      } catch (e) {}
      syncMiniHudState(true);
    }
  }

  function toggleUiPref(key) {
    if (!uiPrefs) return;
    const hudKeys = ['hudFps', 'hudCpu', 'hudGpu', 'hudRam', 'hudNet', 'hudTimer'];
    const dashTopKeys = ['dashCpu', 'dashRam', 'dashGpu', 'dashFps', 'dashNetDisk', 'dashProcs', 'dashPomo'];

    const normalizedKey = (key === 'dashProcesses') ? 'dashProcs' : ((key === 'dashProductivity') ? 'dashPomo' : key);

    // 최소 1개 항목은 켜져 있도록 보호
    if (hudKeys.includes(normalizedKey) && uiPrefs[normalizedKey] !== false) {
      const remaining = hudKeys.filter(k => k !== normalizedKey && uiPrefs[k] !== false).length;
      if (remaining === 0) {
        showToast('⚠️ 미니 HUD에는 최소 1개 이상의 모니터링 항목이 표시되어야 합니다.');
        return;
      }
    }
    if (dashTopKeys.includes(normalizedKey) && uiPrefs[normalizedKey] !== false) {
      const remaining = dashTopKeys.filter(k => k !== normalizedKey && uiPrefs[k] !== false).length;
      if (remaining === 0) {
        showToast('⚠️ 메인 대시보드에는 최소 1개 이상의 패널이 표시되어야 합니다.');
        return;
      }
    }

    const nextVal = !(uiPrefs[normalizedKey] !== false);
    uiPrefs[normalizedKey] = nextVal;
    if (normalizedKey === 'dashProcs') uiPrefs.dashProcesses = nextVal;
    if (normalizedKey === 'dashPomo') uiPrefs.dashProductivity = nextVal;

    saveUiPrefs();
    applyUiPrefs(true);
  }

  function setMiniHudStylePref(isWide) {
    if (!uiPrefs) return;
    const wideBool = (isWide === 'bar' || isWide === true || isWide === 1);
    uiPrefs.hudLayoutWide = wideBool;
    miniHudWideLayout = wideBool;
    saveUiPrefs();
    applyUiPrefs(true);
    syncMiniHudState(isMiniHudMode);
    showToast(wideBool
      ? '📏 미니 HUD 모양이 [슬림 가로 바형 (1줄)]으로 설정되었습니다.'
      : '📦 미니 HUD 모양이 [컴팩트 박스형 (2줄)]으로 설정되었습니다.');
  }

  function applyUiPreset(preset) {
    if (preset === 'all') {
      uiPrefs = normalizeUiPrefsObj(Object.assign({}, DEFAULT_UI_PREFS, {
        hudLayoutWide: uiPrefs.hudLayoutWide,
        hudTopmost: uiPrefs.hudTopmost
      }));
      showToast('✨ [전체 다 보기] 프리셋이 적용되었습니다.');
    } else if (preset === 'gamer') {
      uiPrefs = normalizeUiPrefsObj(Object.assign({}, uiPrefs, {
        dashCpu: true,
        dashRam: false,
        dashGpu: true,
        dashFps: true,
        dashNetDisk: true,
        dashProcs: false,
        dashPomo: false,
        hudLayoutWide: true,
        hudFps: true,
        hudCpu: true,
        hudGpu: true,
        hudRam: false,
        hudNet: true,
        hudTimer: false
      }));
      showToast('🎮 [게이머 핵심 (FPS·GPU·CPU·핑 + 가로바 HUD)] 프리셋이 적용되었습니다.');
    } else if (preset === 'minimal') {
      uiPrefs = normalizeUiPrefsObj(Object.assign({}, uiPrefs, {
        dashCpu: true,
        dashRam: false,
        dashGpu: true,
        dashFps: true,
        dashNetDisk: false,
        dashProcs: false,
        dashPomo: false,
        hudLayoutWide: true,
        hudFps: true,
        hudCpu: true,
        hudGpu: true,
        hudRam: false,
        hudNet: false,
        hudTimer: false
      }));
      showToast('⚡ [초경량 미니멀 (CPU·GPU·FPS 3대 핵심)] 프리셋이 적용되었습니다.');
    } else if (preset === 'work') {
      uiPrefs = normalizeUiPrefsObj(Object.assign({}, uiPrefs, {
        dashCpu: true,
        dashRam: true,
        dashGpu: false,
        dashFps: false,
        dashNetDisk: true,
        dashProcs: true,
        dashPomo: true,
        hudLayoutWide: false,
        hudFps: false,
        hudCpu: true,
        hudGpu: false,
        hudRam: true,
        hudNet: true,
        hudTimer: true
      }));
      showToast('💼 [작업·업무 집중 (CPU·RAM·프로세스·할 일 보드)] 프리셋이 적용되었습니다.');
    }
    saveUiPrefs();
    applyUiPrefs(true);
    syncMiniHudState(isMiniHudMode);
  }

  function resetUiPrefs() {
    uiPrefs = normalizeUiPrefsObj(DEFAULT_UI_PREFS);
    saveUiPrefs();
    applyUiPrefs(true);
    syncMiniHudState(isMiniHudMode);
    showToast('🔄 화면 및 미니 HUD 맞춤 설정이 기본값으로 초기화되었습니다.');
  }

  function openUiSettingsModal() {
    closeDetailView();
    closeRecordAnalysis();
    closeAlertSettings();
    closeGameScanModal();
    closeUpdateModal();
    closeHelpModal();
    applyUiPrefs(false);
    const overlay = document.getElementById('uisettings-overlay');
    if (overlay) overlay.classList.remove('hidden');
    ['overview', 'system', 'netdisk', 'gamelog', 'productivity', 'analysis', 'alerts', 'uisettings', 'help'].forEach(t => {
      const ch = document.getElementById('chan-' + t);
      const rl = document.getElementById('rail-' + t);
      if (ch) ch.classList.toggle('active', t === 'uisettings');
      if (rl) rl.classList.toggle('active', t === 'uisettings');
    });
  }

  function closeUiSettingsModal() {
    const overlay = document.getElementById('uisettings-overlay');
    if (overlay && !overlay.classList.contains('hidden')) {
      overlay.classList.add('hidden');
      ['overview', 'system', 'netdisk', 'gamelog', 'productivity', 'analysis', 'alerts', 'uisettings', 'help'].forEach(t => {
        const ch = document.getElementById('chan-' + t);
        const rl = document.getElementById('rail-' + t);
        if (ch) ch.classList.toggle('active', t === activeMainTab);
        if (rl) rl.classList.toggle('active', t === activeMainTab);
      });
    }
  }

  async function openUiSettingsFromMiniHud() {
    if (isMiniHudMode) {
      await exitMiniHudMode();
    }
    openUiSettingsModal();
  }

  // ==================== GitHub Releases 기반 자동 업데이트 ====================
  let latestUpdateInfo = null;

  function openUpdateModal(forceCheck = false) {
    closeDetailView();
    closeRecordAnalysis();
    closeAlertSettings();
    closeGameScanModal();
    closeUiSettingsModal();
    closeHelpModal();
    const overlay = document.getElementById('update-overlay');
    if (overlay) overlay.classList.remove('hidden');
    if (forceCheck || !latestUpdateInfo) {
      checkForUpdates(true);
    } else {
      renderUpdateModal(latestUpdateInfo);
    }
  }

  function closeUpdateModal() {
    const overlay = document.getElementById('update-overlay');
    if (overlay && !overlay.classList.contains('hidden')) {
      overlay.classList.add('hidden');
    }
  }

  function openGithubPage(url) {
    apiFetch(`/api/open_external?url=${encodeURIComponent(url)}`, { method: 'POST' }).catch(() => {});
  }

  async function checkForUpdates(isManual = false) {
    const latestBadge = document.getElementById('upd-latest-badge');
    const headline = document.getElementById('upd-status-headline');
    if (isManual) {
      if (latestBadge) {
        latestBadge.textContent = '확인 중...';
        latestBadge.style.color = 'var(--text-muted)';
      }
      if (headline) headline.textContent = 'GitHub (neverloselkb/coreFlow) 서버에서 최신 릴리스 정보를 조회하고 있습니다...';
    }

    try {
      const res = await apiFetch('/api/check_update');
      const data = await res.json();
      if (!data.ok) {
        if (isManual && headline) {
          headline.textContent = `⚠️ 업데이트 확인 실패: ${data.error || '네트워크 연결을 확인해 주세요.'}`;
        }
        return;
      }
      latestUpdateInfo = data;
      renderUpdateModal(data);

      const topBtn = document.getElementById('btn-update-check');
      const topBtnText = document.getElementById('btn-update-text');
      const banner = document.getElementById('update-notify-banner');
      const bannerTitle = document.getElementById('update-banner-title');
      const bannerDesc = document.getElementById('update-banner-desc');

      if (data.has_update) {
        if (topBtn && topBtnText) {
          topBtn.classList.remove('secondary');
          topBtn.style.borderColor = 'var(--neon-green)';
          topBtn.style.backgroundColor = 'rgba(0, 200, 117, 0.18)';
          topBtn.style.color = 'var(--neon-green)';
          topBtnText.textContent = `NEW v${data.latest_version}`;
        }
        if (banner && bannerTitle && bannerDesc) {
          bannerTitle.textContent = `🎉 새로운 CoreFlow v${data.latest_version} 업데이트가 출시되었습니다! (현재 v${data.current_version})`;
          bannerDesc.textContent = `원클릭 자동 업데이트로 모든 설정과 게임 플레이 기록을 유지한 채 즉시 최신 버전으로 업그레이드할 수 있습니다.`;
          banner.classList.remove('hidden');
        }
        if (isManual) {
          showToast(`🎉 새 버전(v${data.latest_version})이 감지되었습니다!`);
        }
      } else if (isManual) {
        showToast(`✅ 현재 최신 버전(v${data.current_version})을 사용 중입니다.`);
      }
    } catch (e) {
      if (isManual && headline) {
        headline.textContent = '⚠️ GitHub 서버와 통신하는 중 오류가 발생했습니다.';
      }
    }
  }

  function renderUpdateModal(data) {
    const curBadge = document.getElementById('upd-current-badge');
    const latestBadge = document.getElementById('upd-latest-badge');
    const headline = document.getElementById('upd-status-headline');
    const notesEl = document.getElementById('upd-release-notes');
    const tagEl = document.getElementById('upd-tag-label');
    const btnDoUpdate = document.getElementById('btn-do-update');

    if (curBadge) curBadge.textContent = `현재 v${data.current_version}`;
    if (tagEl) tagEl.textContent = data.tag_name ? `Tag: ${data.tag_name}` : 'neverloselkb/coreFlow';
    if (notesEl) {
      notesEl.textContent = (data.notes && data.notes.trim())
        ? data.notes
        : '등록된 릴리스 노트가 없습니다.';
    }

    if (data.has_update) {
      if (latestBadge) {
        latestBadge.textContent = `🚀 최신 v${data.latest_version} 업데이트 가능`;
        latestBadge.style.color = 'var(--neon-green)';
      }
      if (headline) {
        headline.innerHTML = `<strong style="color:var(--neon-green);">새로운 버전(v${escapeHtml(data.latest_version)})이 배포되었습니다!</strong> 우측 버튼을 누르면 자동으로 다운로드 및 설치 후 재시작됩니다.`;
      }
      if (btnDoUpdate) {
        btnDoUpdate.style.display = 'inline-flex';
        btnDoUpdate.disabled = false;
        btnDoUpdate.textContent = `🚀 v${data.latest_version} 원클릭 자동 업데이트`;
      }
    } else {
      if (latestBadge) {
        latestBadge.textContent = `✅ 최신 버전 사용 중 (v${data.current_version})`;
        latestBadge.style.color = 'var(--brand)';
      }
      if (headline) {
        headline.textContent = '현재 설치된 CoreFlow가 가장 최신 버전입니다.';
      }
      if (btnDoUpdate) {
        btnDoUpdate.style.display = 'none';
      }
    }
  }

  async function triggerSelfUpdate() {
    if (!latestUpdateInfo || !latestUpdateInfo.download_url) {
      showToast('⚠️ 업데이트 다운로드 경로를 찾을 수 없습니다.');
      return;
    }
    const btn = document.getElementById('btn-do-update');
    const headline = document.getElementById('upd-status-headline');
    if (btn) {
      btn.disabled = true;
      btn.textContent = '⏳ GitHub에서 최신 버전 다운로드 및 설치 중...';
    }
    if (headline) {
      headline.innerHTML = '<strong style="color:var(--brand);">GitHub Releases에서 최신 업데이트 패키지를 다운로드하고 있습니다. 완료되면 프로그램이 자동으로 재시작됩니다...</strong>';
    }
    try {
      const res = await apiFetch(`/api/perform_update?url=${encodeURIComponent(latestUpdateInfo.download_url)}`, { method: 'POST' });
      const data = await res.json();
      if (data.ok) {
        showToast('🚀 다운로드 완료! 기존 창을 닫고 최신 버전으로 자동 재시작합니다...');
        setTimeout(() => {
          window.close();
        }, 300);
      } else {
        showToast(`⚠️ 업데이트 실패: ${data.error || '알 수 없는 오류'}`);
        if (headline) headline.textContent = `❌ ${data.error || '업데이트에 실패했습니다.'}`;
        if (btn) {
          btn.disabled = false;
          btn.textContent = `🚀 v${latestUpdateInfo.latest_version} 원클릭 자동 업데이트`;
        }
      }
    } catch (e) {
      showToast('⚠️ 업데이트 요청 중 오류가 발생했습니다.');
      if (btn) {
        btn.disabled = false;
        btn.textContent = '다시 시도';
      }
    }
  }

  function quitApp() {
    navigator.sendBeacon('/api/quit?' + getWindowBoundsQuery());
    window.close();
  }

  window.addEventListener('pagehide', () => {
    navigator.sendBeacon('/api/quit?' + getWindowBoundsQuery());
  });

  document.getElementById('theme-mode-select').value = themeOverride;
  applyWindowsTheme(lastWinTheme);
  renderTodos();
  updatePomoUI();
  applyUiPrefs(false);
  initMiniHudModeFromSaved();
  applyDashboardViewMode();
  fetchStats();
  setInterval(fetchStats, 1000);
  setTimeout(() => checkForUpdates(false), 3000);
</script>
</body>
</html>
"#;
