#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    println!("CoreFlow_Setup is only supported on Windows.");
}

#[cfg(windows)]
mod win_setup {
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::System;

const CREATE_NO_WINDOW: u32 = 0x08000000;

/// 내장된 최신 CoreFlow 릴리스 실행 파일 및 아이콘 리소스
const EMBEDDED_COREFLOW_EXE: &[u8] = include_bytes!("../../target/release/CoreFlow.exe");
const EMBEDDED_ICON_ICO: &[u8] = include_bytes!("../../assets/coreflow.ico");

#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

const CLSID_SHELL_LINK: Guid = Guid {
    data1: 0x00021401,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

const IID_ISHELL_LINK_W: Guid = Guid {
    data1: 0x000214F9,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

const IID_IPERSIST_FILE: Guid = Guid {
    data1: 0x0000010B,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

#[repr(C)]
struct IShellLinkWVtbl {
    query_interface:
        unsafe extern "system" fn(*mut IShellLinkW, *const Guid, *mut *mut std::ffi::c_void) -> i32,
    add_ref: unsafe extern "system" fn(*mut IShellLinkW) -> u32,
    release: unsafe extern "system" fn(*mut IShellLinkW) -> u32,
    get_path: *const std::ffi::c_void,
    get_id_list: *const std::ffi::c_void,
    set_id_list: *const std::ffi::c_void,
    get_description: *const std::ffi::c_void,
    set_description: unsafe extern "system" fn(*mut IShellLinkW, *const u16) -> i32,
    get_working_directory: *const std::ffi::c_void,
    set_working_directory: unsafe extern "system" fn(*mut IShellLinkW, *const u16) -> i32,
    get_arguments: *const std::ffi::c_void,
    set_arguments: unsafe extern "system" fn(*mut IShellLinkW, *const u16) -> i32,
    get_hotkey: *const std::ffi::c_void,
    set_hotkey: *const std::ffi::c_void,
    get_show_cmd: *const std::ffi::c_void,
    set_show_cmd: *const std::ffi::c_void,
    get_icon_location: *const std::ffi::c_void,
    set_icon_location: unsafe extern "system" fn(*mut IShellLinkW, *const u16, i32) -> i32,
    set_relative_path: *const std::ffi::c_void,
    resolve: *const std::ffi::c_void,
    set_path: unsafe extern "system" fn(*mut IShellLinkW, *const u16) -> i32,
}

#[repr(C)]
struct IShellLinkW {
    lp_vtbl: *const IShellLinkWVtbl,
}

#[repr(C)]
struct IPersistFileVtbl {
    query_interface: *const std::ffi::c_void,
    add_ref: *const std::ffi::c_void,
    release: unsafe extern "system" fn(*mut IPersistFile) -> u32,
    get_class_id: *const std::ffi::c_void,
    is_dirty: *const std::ffi::c_void,
    load: *const std::ffi::c_void,
    save: unsafe extern "system" fn(*mut IPersistFile, *const u16, i32) -> i32,
    save_completed: *const std::ffi::c_void,
    get_cur_file: *const std::ffi::c_void,
}

#[repr(C)]
struct IPersistFile {
    lp_vtbl: *const IPersistFileVtbl,
}

#[link(name = "Ole32")]
extern "system" {
    fn CoInitializeEx(pv_reserved: *mut std::ffi::c_void, dw_co_init: u32) -> i32;
    fn CoUninitialize();
    fn CoCreateInstance(
        rclsid: *const Guid,
        p_unk_outer: *mut std::ffi::c_void,
        dw_cls_context: u32,
        riid: *const Guid,
        ppv: *mut *mut std::ffi::c_void,
    ) -> i32;
    fn CoTaskMemFree(pv: *mut std::ffi::c_void);
}

#[repr(C)]
struct BrowseInfoW {
    hwnd_owner: isize,
    pidl_root: *const std::ffi::c_void,
    psz_display_name: *mut u16,
    lpsz_title: *const u16,
    ul_flags: u32,
    lpfn: Option<unsafe extern "system" fn(isize, u32, isize, isize) -> i32>,
    l_param: isize,
    i_image: i32,
}

#[link(name = "Shell32")]
extern "system" {
    fn IsUserAnAdmin() -> i32;
    fn ShellExecuteW(
        hwnd: isize,
        lp_operation: *const u16,
        lp_file: *const u16,
        lp_parameters: *const u16,
        lp_directory: *const u16,
        n_show_cmd: i32,
    ) -> isize;
    fn SHBrowseForFolderW(lpbi: *mut BrowseInfoW) -> *mut std::ffi::c_void;
    fn SHGetPathFromIDListW(pidl: *const std::ffi::c_void, psz_path: *mut u16) -> i32;
}

#[link(name = "Advapi32")]
extern "system" {
    fn RegCreateKeyExW(
        h_key: isize,
        lp_sub_key: *const u16,
        reserved: u32,
        lp_class: *const u16,
        dw_options: u32,
        sam_desired: u32,
        lp_security_attributes: *const std::ffi::c_void,
        phk_result: *mut isize,
        lpdw_disposition: *mut u32,
    ) -> i32;
    fn RegOpenKeyExW(
        h_key: isize,
        lp_sub_key: *const u16,
        ul_options: u32,
        sam_desired: u32,
        phk_result: *mut isize,
    ) -> i32;
    fn RegSetValueExW(
        h_key: isize,
        lp_value_name: *const u16,
        reserved: u32,
        dw_type: u32,
        lp_data: *const u8,
        cb_data: u32,
    ) -> i32;
    fn RegDeleteValueW(h_key: isize, lp_value_name: *const u16) -> i32;
    fn RegQueryValueExW(
        h_key: isize,
        lp_value_name: *const u16,
        lp_reserved: *mut u32,
        lp_type: *mut u32,
        lp_data: *mut u8,
        lpcb_data: *mut u32,
    ) -> i32;
    fn RegDeleteKeyW(h_key: isize, lp_sub_key: *const u16) -> i32;
    fn RegCloseKey(h_key: isize) -> i32;
}

#[link(name = "User32")]
extern "system" {
    fn FindWindowW(lp_class_name: *const u16, lp_window_name: *const u16) -> isize;
    fn PostMessageW(h_wnd: isize, msg: u32, w_param: usize, l_param: isize) -> i32;
    fn GetForegroundWindow() -> isize;
    fn SetForegroundWindow(h_wnd: isize) -> i32;
    fn LoadImageW(
        h_inst: isize,
        name: *const u16,
        type_: u32,
        cx: i32,
        cy: i32,
        fu_load: u32,
    ) -> isize;
    fn SendMessageW(h_wnd: isize, msg: u32, w_param: usize, l_param: isize) -> isize;
}

const HKEY_CURRENT_USER: isize = -2147483647i32 as isize;
const KEY_SET_VALUE: u32 = 0x0002;
const KEY_QUERY_VALUE: u32 = 0x0001;
const KEY_WRITE: u32 = 0x20006;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 순수 Win32 COM (`IShellLinkW` + `IPersistFile`)을 사용하여 `.lnk` 바로가기 파일 생성
fn create_windows_shortcut(
    lnk_path: &Path,
    target_exe: &Path,
    work_dir: &Path,
    icon_path: &Path,
    description: &str,
) -> bool {
    let target_w = to_wide_null(&target_exe.to_string_lossy());
    let work_w = to_wide_null(&work_dir.to_string_lossy());
    let icon_w = to_wide_null(&icon_path.to_string_lossy());
    let desc_w = to_wide_null(description);
    let lnk_w = to_wide_null(&lnk_path.to_string_lossy());

    unsafe {
        let _ = CoInitializeEx(std::ptr::null_mut(), 2); // COINIT_APARTMENTTHREADED
        let mut p_sl: *mut IShellLinkW = std::ptr::null_mut();
        let hr = CoCreateInstance(
            &CLSID_SHELL_LINK,
            std::ptr::null_mut(),
            1, // CLSCTX_INPROC_SERVER
            &IID_ISHELL_LINK_W,
            &mut p_sl as *mut *mut IShellLinkW as *mut *mut std::ffi::c_void,
        );
        if hr < 0 || p_sl.is_null() {
            CoUninitialize();
            return false;
        }

        let vtbl = &*(*p_sl).lp_vtbl;
        let _ = (vtbl.set_path)(p_sl, target_w.as_ptr());
        let _ = (vtbl.set_working_directory)(p_sl, work_w.as_ptr());
        let _ = (vtbl.set_description)(p_sl, desc_w.as_ptr());
        let _ = (vtbl.set_icon_location)(p_sl, icon_w.as_ptr(), 0);

        let mut p_pf: *mut IPersistFile = std::ptr::null_mut();
        let hr_qi = (vtbl.query_interface)(
            p_sl,
            &IID_IPERSIST_FILE,
            &mut p_pf as *mut *mut IPersistFile as *mut *mut std::ffi::c_void,
        );

        let mut saved_ok = false;
        if hr_qi >= 0 && !p_pf.is_null() {
            let pf_vtbl = &*(*p_pf).lp_vtbl;
            let hr_save = (pf_vtbl.save)(p_pf, lnk_w.as_ptr(), 1);
            saved_ok = hr_save >= 0;
            let _ = (pf_vtbl.release)(p_pf);
        }

        let _ = (vtbl.release)(p_sl);
        CoUninitialize();
        saved_ok
    }
}

fn reg_set_sz(hkey: isize, name: &str, value: &str) -> bool {
    let name_w = to_wide_null(name);
    let val_w = to_wide_null(value);
    unsafe {
        RegSetValueExW(
            hkey,
            name_w.as_ptr(),
            0,
            REG_SZ,
            val_w.as_ptr() as *const u8,
            (val_w.len() * 2) as u32,
        ) == 0
    }
}

fn reg_set_dword(hkey: isize, name: &str, value: u32) -> bool {
    let name_w = to_wide_null(name);
    unsafe {
        RegSetValueExW(
            hkey,
            name_w.as_ptr(),
            0,
            REG_DWORD,
            &value as *const u32 as *const u8,
            4,
        ) == 0
    }
}

/// Windows '설치된 앱(프로그램 추가/제거)' 레지스트리 등록
fn register_uninstaller(install_dir: &Path, exe_path: &Path, uninstaller_path: &Path) -> bool {
    let subkey = to_wide_null("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\CoreFlow");
    let mut hkey: isize = 0;
    let mut disp: u32 = 0;
    unsafe {
        if RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_WRITE,
            std::ptr::null(),
            &mut hkey,
            &mut disp,
        ) != 0
        {
            return false;
        }
        let icon_str = exe_path.to_string_lossy().to_string();
        let loc_str = install_dir.to_string_lossy().to_string();
        let uninst_cmd = format!("\"{}\" --uninstall", uninstaller_path.to_string_lossy());
        let size_kb = ((EMBEDDED_COREFLOW_EXE.len() + EMBEDDED_ICON_ICO.len()) / 1024) as u32;

        reg_set_sz(hkey, "DisplayName", "CoreFlow — 시스템 모니터링 & 게이밍 스튜디오");
        reg_set_sz(hkey, "DisplayVersion", env!("CARGO_PKG_VERSION"));
        reg_set_sz(hkey, "Publisher", "CoreFlow Studio");
        reg_set_sz(hkey, "DisplayIcon", &icon_str);
        reg_set_sz(hkey, "InstallLocation", &loc_str);
        reg_set_sz(hkey, "UninstallString", &uninst_cmd);
        reg_set_sz(hkey, "QuietUninstallString", &uninst_cmd);
        reg_set_dword(hkey, "NoModify", 1);
        reg_set_dword(hkey, "NoRepair", 1);
        reg_set_dword(hkey, "EstimatedSize", size_kb);

        let _ = RegCloseKey(hkey);
    }
    true
}

fn unregister_uninstaller() {
    let subkey = to_wide_null("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\CoreFlow");
    unsafe {
        let _ = RegDeleteKeyW(HKEY_CURRENT_USER, subkey.as_ptr());
    }
}

fn set_startup_autorun(enable: bool, exe_path: &Path) {
    let subkey = to_wide_null("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    let legacy_name = to_wide_null("CoreFlowMonitor");
    let val_name = to_wide_null("CoreFlow");
    let mut hkey: isize = 0;
    unsafe {
        if RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_SET_VALUE, &mut hkey) == 0 {
            // 구버전 설치 관리자 항목(CoreFlowMonitor)은 항상 정리하고 앱과 동일한 'CoreFlow' 항목으로 통합
            let _ = RegDeleteValueW(hkey, legacy_name.as_ptr());
            if enable {
                let cmd = format!("\"{}\"", exe_path.to_string_lossy());
                reg_set_sz(hkey, "CoreFlow", &cmd);
            } else {
                let _ = RegDeleteValueW(hkey, val_name.as_ptr());
            }
            let _ = RegCloseKey(hkey);
        }
    }
}

/// 업데이트 시 기존 시작 프로그램 등록 여부를 유지하면서 경로만 새 설치 경로로 갱신
fn refresh_startup_autorun_path(exe_path: &Path) {
    let subkey = to_wide_null("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    let mut hkey: isize = 0;
    let mut exists = false;
    unsafe {
        if RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_QUERY_VALUE, &mut hkey) == 0 {
            for name in ["CoreFlow", "CoreFlowMonitor"] {
                let n = to_wide_null(name);
                let mut ty: u32 = 0;
                let mut size: u32 = 0;
                if RegQueryValueExW(hkey, n.as_ptr(), std::ptr::null_mut(), &mut ty, std::ptr::null_mut(), &mut size) == 0 {
                    exists = true;
                }
            }
            let _ = RegCloseKey(hkey);
        }
    }
    if exists {
        set_startup_autorun(true, exe_path);
    }
}

fn default_install_dir() -> PathBuf {
    PathBuf::from(r"C:\Program Files\CoreFlow")
}

unsafe extern "system" fn browse_callback_proc(
    hwnd: isize,
    u_msg: u32,
    _l_param: isize,
    lp_data: isize,
) -> i32 {
    const BFFM_INITIALIZED: u32 = 1;
    const BFFM_SETSELECTIONW: u32 = 0x0400 + 103;
    if u_msg == BFFM_INITIALIZED && lp_data != 0 {
        let _ = SetForegroundWindow(hwnd);
        let _ = SendMessageW(hwnd, BFFM_SETSELECTIONW, 1, lp_data);
    }
    0
}

/// 네이티브 Windows 폴더 선택 대화상자(`SHBrowseForFolderW`)를 띄워 설치 경로를 선택
fn browse_for_install_folder(current_dir_str: &str) -> Option<String> {
    let mut initial_dir = PathBuf::from(current_dir_str.trim());
    while !initial_dir.as_os_str().is_empty() && !initial_dir.exists() {
        if let Some(parent) = initial_dir.parent() {
            if parent.as_os_str().is_empty() {
                break;
            }
            initial_dir = parent.to_path_buf();
        } else {
            break;
        }
    }
    if !initial_dir.exists() {
        initial_dir = PathBuf::from(r"C:\Program Files");
    }

    let init_w = to_wide_null(&initial_dir.to_string_lossy());
    let title_w = to_wide_null("CoreFlow를 설치할 폴더를 선택하세요 (하위에 CoreFlow 폴더가 자동 지정됩니다):");
    let win_title_w = to_wide_null("CoreFlow Setup — 설치 및 관리 마법사");

    unsafe {
        let _ = CoInitializeEx(std::ptr::null_mut(), 2); // COINIT_APARTMENTTHREADED
        let mut hwnd_owner = FindWindowW(std::ptr::null(), win_title_w.as_ptr());
        if hwnd_owner == 0 {
            hwnd_owner = GetForegroundWindow();
        }

        let mut display_name = [0u16; 260];
        // BIF_RETURNONLYFSDIRS (0x0001) | BIF_EDITBOX (0x0010) | BIF_NEWDIALOGSTYLE (0x0040)
        let mut bi = BrowseInfoW {
            hwnd_owner,
            pidl_root: std::ptr::null(),
            psz_display_name: display_name.as_mut_ptr(),
            lpsz_title: title_w.as_ptr(),
            ul_flags: 0x0001 | 0x0010 | 0x0040,
            lpfn: Some(browse_callback_proc),
            l_param: init_w.as_ptr() as isize,
            i_image: 0,
        };

        let pidl = SHBrowseForFolderW(&mut bi);
        if pidl.is_null() {
            CoUninitialize();
            return None;
        }

        let mut path_buf = [0u16; 520];
        let ok = SHGetPathFromIDListW(pidl, path_buf.as_mut_ptr());
        CoTaskMemFree(pidl);
        CoUninitialize();

        if ok == 0 {
            return None;
        }

        let len = path_buf.iter().position(|&c| c == 0).unwrap_or(0);
        let chosen = String::from_utf16_lossy(&path_buf[..len]);
        if chosen.is_empty() {
            return None;
        }

        let chosen_path = PathBuf::from(&chosen);
        let final_path = if chosen_path
            .file_name()
            .map(|n| n.to_string_lossy().eq_ignore_ascii_case("CoreFlow"))
            .unwrap_or(false)
        {
            chosen_path
        } else {
            chosen_path.join("CoreFlow")
        };

        Some(final_path.to_string_lossy().to_string())
    }
}

fn desktop_shortcut_path() -> PathBuf {
    let user_profile = env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".to_string());
    let one_drive_desk = PathBuf::from(&user_profile).join("OneDrive").join("Desktop");
    let std_desk = PathBuf::from(&user_profile).join("Desktop");
    if std_desk.exists() {
        std_desk.join("CoreFlow.lnk")
    } else if one_drive_desk.exists() {
        one_drive_desk.join("CoreFlow.lnk")
    } else {
        std_desk.join("CoreFlow.lnk")
    }
}

fn start_menu_shortcut_path() -> PathBuf {
    let app_data = env::var("APPDATA").unwrap_or_default();
    PathBuf::from(app_data)
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("CoreFlow.lnk")
}

/// 실행 중인 기존 CoreFlow UI 창(WebView) 및 백엔드 프로세스를 모두 안전하게 종료
fn stop_running_coreflow() -> usize {
    // 1. 열려 있는 기존 CoreFlow UI 창(Edge/Chrome 앱 창) 닫기
    const WM_CLOSE: u32 = 0x0010;
    let app_title_w = to_wide_null("CoreFlow — 시스템 모니터링 & 집중 스튜디오");
    for _ in 0..8 {
        let hwnd = unsafe { FindWindowW(std::ptr::null(), app_title_w.as_ptr()) };
        if hwnd == 0 {
            break;
        }
        unsafe {
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
        }
        thread::sleep(Duration::from_millis(120));
    }

    // 2. 실행 중인 모든 CoreFlow.exe (감시자 및 워커) 프로세스 종료
    let mut sys = System::new_all();
    sys.refresh_all();
    let my_pid = std::process::id();
    let mut killed = 0usize;
    for (pid, proc_info) in sys.processes() {
        if pid.as_u32() == my_pid {
            continue;
        }
        let name_lower = proc_info.name().to_string_lossy().to_lowercase();
        if name_lower == "coreflow.exe" || name_lower == "coreflow" {
            if proc_info.kill() {
                killed += 1;
            }
        }
    }

    thread::sleep(Duration::from_millis(500));
    killed
}

/// 기존 작업 폴더의 사용자 설정 및 게임 플레이 로그를 설치 폴더로 마이그레이션
fn migrate_user_data(target_dir: &Path) -> usize {
    let mut copied = 0usize;
    let Ok(cur_dir) = env::current_dir() else {
        return 0;
    };
    if cur_dir == target_dir {
        return 0;
    }

    let config_files = [
        "coreflow_todos.json",
        "coreflow_alerts.json",
        "coreflow_ui_prefs.json",
        "coreflow_custom_games.json",
        "coreflow_minihud_state.json",
        "rustcord_theme_pref.cfg",
        "rustcord_window_bounds.cfg",
        "custom_avatar.img",
    ];
    for file_name in &config_files {
        let src = cur_dir.join(file_name);
        let dst = target_dir.join(file_name);
        if src.exists() && !dst.exists() {
            if fs::copy(&src, &dst).is_ok() {
                copied += 1;
            }
        }
    }

    let src_logs = cur_dir.join("logs");
    let dst_logs = target_dir.join("logs");
    if src_logs.is_dir() {
        let _ = fs::create_dir_all(&dst_logs);
        if let Ok(entries) = fs::read_dir(&src_logs) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    if let Some(fname) = p.file_name() {
                        let dst_file = dst_logs.join(fname);
                        if !dst_file.exists() && fs::copy(&p, &dst_file).is_ok() {
                            copied += 1;
                        }
                    }
                }
            }
        }
    }
    copied
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn url_decode(s: &str) -> String {
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.as_bytes().iter().copied();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next();
            let h2 = chars.next();
            if let (Some(c1), Some(c2)) = (h1, h2) {
                let hex = [c1, c2];
                if let Ok(hex_str) = std::str::from_utf8(&hex) {
                    if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                        bytes.push(val);
                        continue;
                    }
                }
            }
            bytes.push(b'%');
        } else if b == b'+' {
            bytes.push(b' ');
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8_lossy(&bytes).to_string()
}

fn parse_query_str(request_line: &str, key: &str) -> Option<String> {
    let path = request_line.split_whitespace().nth(1)?;
    let query = path.split('?').nth(1)?;
    let prefix = format!("{key}=");
    for pair in query.split('&') {
        if let Some(val) = pair.strip_prefix(&prefix) {
            return Some(url_decode(val));
        }
    }
    None
}

fn perform_install(
    install_dir_str: &str,
    opt_desktop: bool,
    opt_start_menu: bool,
    opt_uninstaller: bool,
    opt_startup: Option<bool>,
    opt_migrate: bool,
    opt_launch: bool,
) -> String {
    let mut steps = Vec::new();
    let install_dir = PathBuf::from(install_dir_str.trim());
    if install_dir.as_os_str().is_empty() {
        return r#"{"ok":false,"error":"설치 경로가 비어 있습니다."}"#.to_string();
    }

    // 1. 실행 중인 CoreFlow 종료
    let killed = stop_running_coreflow();
    if killed > 0 {
        steps.push(format!("실행 중인 CoreFlow 프로세스 {}개 안전 종료 완료", killed));
    } else {
        steps.push("실행 중인 충돌 프로세스 없음 확인".to_string());
    }

    // 2. 설치 디렉토리 및 하위 폴더 생성
    if let Err(e) = fs::create_dir_all(&install_dir) {
        return format!(
            r#"{{"ok":false,"error":"설치 폴더 생성 실패: {}"}}"#,
            escape_json(&e.to_string())
        );
    }
    let assets_dir = install_dir.join("assets");
    let logs_dir = install_dir.join("logs");
    let _ = fs::create_dir_all(&assets_dir);
    let _ = fs::create_dir_all(&logs_dir);
    steps.push(format!("설치 디렉토리 생성 완료: {}", install_dir.display()));

    // 3. CoreFlow.exe 및 아이콘 추출
    let exe_path = install_dir.join("CoreFlow.exe");
    let ico_path = assets_dir.join("coreflow.ico");
    let root_ico_path = install_dir.join("coreflow.ico");

    if let Err(e) = fs::write(&exe_path, EMBEDDED_COREFLOW_EXE) {
        return format!(
            r#"{{"ok":false,"error":"CoreFlow.exe 파일 쓰기 실패: {}"}}"#,
            escape_json(&e.to_string())
        );
    }
    let _ = fs::write(&ico_path, EMBEDDED_ICON_ICO);
    let _ = fs::write(&root_ico_path, EMBEDDED_ICON_ICO);
    steps.push(format!(
        "CoreFlow.exe ({:.2} MB) 및 아이콘 리소스 설치 완료",
        EMBEDDED_COREFLOW_EXE.len() as f64 / (1024.0 * 1024.0)
    ));

    // 4. 언인스톨러(Uninstall_CoreFlow.exe) 최신 버전으로 복사·교체
    let uninst_path = install_dir.join("Uninstall_CoreFlow.exe");
    if let Ok(self_exe) = env::current_exe() {
        let same_uninst = fs::canonicalize(&self_exe)
            .ok()
            .zip(fs::canonicalize(&uninst_path).ok())
            .map(|(a, b)| a == b)
            .unwrap_or(false);
        if !same_uninst {
            let old_uninst = install_dir.join("Uninstall_CoreFlow.old");
            let _ = fs::remove_file(&old_uninst);
            if fs::copy(&self_exe, &uninst_path).is_err() {
                let _ = fs::rename(&uninst_path, &old_uninst);
                let _ = fs::copy(&self_exe, &uninst_path);
                let _ = fs::remove_file(&old_uninst);
            }
        }
    }
    steps.push(format!(
        "전용 언인스톨러 (Uninstall_CoreFlow.exe v{}) 갱신 완료",
        env!("CARGO_PKG_VERSION")
    ));

    // 5. 기존 사용자 데이터 마이그레이션
    if opt_migrate {
        let migrated = migrate_user_data(&install_dir);
        if migrated > 0 {
            steps.push(format!(
                "기존 설정 및 게임 플레이 로그 파일 {}개 마이그레이션 완료",
                migrated
            ));
        } else {
            steps.push("기존 데이터 보존 설정 확인 완료".to_string());
        }
    }

    // 6. 바탕화면 바로가기 생성
    if opt_desktop {
        let desk_lnk = desktop_shortcut_path();
        if create_windows_shortcut(
            &desk_lnk,
            &exe_path,
            &install_dir,
            &ico_path,
            "CoreFlow — 시스템 하드웨어 & 게이밍 모니터",
        ) {
            steps.push(format!("바탕화면 바로가기 생성 완료 ({})", desk_lnk.display()));
        }
    }

    // 7. 시작 메뉴 바로가기 생성
    if opt_start_menu {
        let sm_lnk = start_menu_shortcut_path();
        if let Some(parent) = sm_lnk.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if create_windows_shortcut(
            &sm_lnk,
            &exe_path,
            &install_dir,
            &ico_path,
            "CoreFlow — 시스템 하드웨어 & 게이밍 모니터",
        ) {
            steps.push("Windows 시작 메뉴 프로그램 바로가기 등록 완료".to_string());
        }
    }

    // 8. Windows 프로그램 추가/제거 등록
    if opt_uninstaller {
        if register_uninstaller(&install_dir, &exe_path, &uninst_path) {
            steps.push("Windows '설치된 앱(프로그램 추가/제거)' 레지스트리 등록 완료".to_string());
        }
    }

    // 9. Windows 시작 시 자동 실행 설정 (None = 업데이트: 기존 등록 여부 유지 + 경로만 갱신)
    match opt_startup {
        Some(enable) => {
            set_startup_autorun(enable, &exe_path);
            if enable {
                steps.push("Windows 시작 시 자동 실행 등록 완료".to_string());
            }
        }
        None => refresh_startup_autorun_path(&exe_path),
    }

    // 10. 설치 완료 후 바로 실행
    if opt_launch {
        let _ = Command::new(&exe_path)
            .current_dir(&install_dir)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
        steps.push("CoreFlow 애플리케이션 실행 완료 🚀".to_string());
    }

    let steps_json: Vec<String> = steps
        .iter()
        .map(|s| format!("\"{}\"", escape_json(s)))
        .collect();
    format!(
        r#"{{"ok":true,"install_dir":"{}","exe_path":"{}","steps":[{}]}}"#,
        escape_json(&install_dir.to_string_lossy()),
        escape_json(&exe_path.to_string_lossy()),
        steps_json.join(",")
    )
}

fn perform_uninstall(install_dir_str: &str, keep_user_data: bool) -> String {
    let mut steps = Vec::new();
    let install_dir = PathBuf::from(install_dir_str.trim());

    let killed = stop_running_coreflow();
    if killed > 0 {
        steps.push(format!("실행 중인 CoreFlow 프로세스 {}개 종료 완료", killed));
    }

    // 바로가기 삭제
    let desk_lnk = desktop_shortcut_path();
    if desk_lnk.exists() && fs::remove_file(&desk_lnk).is_ok() {
        steps.push("바탕화면 바로가기 아이콘 삭제 완료".to_string());
    }
    let sm_lnk = start_menu_shortcut_path();
    if sm_lnk.exists() && fs::remove_file(&sm_lnk).is_ok() {
        steps.push("시작 메뉴 바로가기 아이콘 삭제 완료".to_string());
    }

    // 레지스트리 정리
    set_startup_autorun(false, &install_dir.join("CoreFlow.exe"));
    unregister_uninstaller();
    steps.push("Windows 시작프로그램 및 설치 정보 레지스트리 제거 완료".to_string());

    // 파일 삭제
    let _ = fs::remove_file(install_dir.join("CoreFlow.exe"));
    let _ = fs::remove_file(install_dir.join("coreflow.ico"));
    let _ = fs::remove_dir_all(install_dir.join("assets"));
    steps.push("CoreFlow 실행 파일 및 리소스 제거 완료".to_string());

    if !keep_user_data {
        let _ = fs::remove_dir_all(install_dir.join("logs"));
        for f in &[
            "coreflow_todos.json",
            "coreflow_alerts.json",
            "coreflow_ui_prefs.json",
            "coreflow_custom_games.json",
            "coreflow_minihud_state.json",
            "rustcord_theme_pref.cfg",
            "rustcord_window_bounds.cfg",
            "custom_avatar.img",
        ] {
            let _ = fs::remove_file(install_dir.join(f));
        }
        let _ = fs::remove_dir(&install_dir);
        steps.push("사용자 설정 및 로그 데이터 전체 삭제 완료".to_string());
    } else {
        steps.push("사용자 설정 및 게임 플레이 로그(logs/)는 안전하게 보존됨".to_string());
    }

    let steps_json: Vec<String> = steps
        .iter()
        .map(|s| format!("\"{}\"", escape_json(s)))
        .collect();
    format!(r#"{{"ok":true,"steps":[{}]}}"#, steps_json.join(","))
}

fn find_browser_executable() -> Option<String> {
    let candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ];
    for path in candidates {
        if Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

fn launch_setup_window(url: &str) {
    let temp_profile = env::temp_dir().join("CoreFlow_Setup_WebView");
    if let Some(browser) = find_browser_executable() {
        let _ = Command::new(browser)
            .arg(format!("--app={url}"))
            .arg("--window-size=680,600")
            .arg("--window-position=260,160")
            .arg(format!("--user-data-dir={}", temp_profile.display()))
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--disable-extensions")
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
    } else {
        unsafe {
            let op_w = to_wide_null("open");
            let url_w = to_wide_null(url);
            let _ = ShellExecuteW(
                0,
                op_w.as_ptr(),
                url_w.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
            );
        }
    }
}

fn spawn_window_icon_applier() {
    thread::spawn(|| {
        let ico_path = env::temp_dir().join("coreflow_setup_icon.ico");
        let _ = fs::write(&ico_path, EMBEDDED_ICON_ICO);
        let ico_w = to_wide_null(&ico_path.to_string_lossy());
        let title_w = to_wide_null("CoreFlow Setup — 설치 및 관리 마법사");

        unsafe {
            let h_icon_big = LoadImageW(0, ico_w.as_ptr(), 1, 256, 256, 0x0010);
            let h_icon_small = LoadImageW(0, ico_w.as_ptr(), 1, 32, 32, 0x0010);
            for _ in 0..40 {
                let hwnd = FindWindowW(std::ptr::null(), title_w.as_ptr());
                if hwnd != 0 {
                    if h_icon_big != 0 {
                        SendMessageW(hwnd, 0x0080, 1, h_icon_big);
                    }
                    if h_icon_small != 0 {
                        SendMessageW(hwnd, 0x0080, 0, h_icon_small);
                    }
                    break;
                }
                thread::sleep(Duration::from_millis(200));
            }
        }
    });
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn handle_client(
    mut stream: TcpStream,
    last_hb: &AtomicU64,
    connected: &AtomicBool,
    initial_uninstall_mode: bool,
) {
    let mut buf = [0u8; 8192];
    let Ok(n) = stream.read(&mut buf) else {
        return;
    };
    if n == 0 {
        return;
    }
    last_hb.store(now_secs(), Ordering::SeqCst);
    connected.store(true, Ordering::SeqCst);

    let req = String::from_utf8_lossy(&buf[..n]);
    let first_line = req.lines().next().unwrap_or("");

    if first_line.starts_with("GET /favicon.ico") {
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: image/x-icon\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            EMBEDDED_ICON_ICO.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(EMBEDDED_ICON_ICO);
    } else if first_line.starts_with("GET /api/ping") {
        let body = r#"{"ok":true}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/install") {
        let dir = parse_query_str(first_line, "dir")
            .unwrap_or_else(|| default_install_dir().to_string_lossy().to_string());
        let desktop = parse_query_str(first_line, "desktop").unwrap_or_default() == "1";
        let startmenu = parse_query_str(first_line, "startmenu").unwrap_or_default() == "1";
        let uninstaller = parse_query_str(first_line, "uninstaller").unwrap_or_default() == "1";
        let startup = parse_query_str(first_line, "startup").unwrap_or_default() == "1";
        let migrate = parse_query_str(first_line, "migrate").unwrap_or_default() == "1";
        let launch = parse_query_str(first_line, "launch").unwrap_or_default() == "1";

        let json = perform_install(
            &dir,
            desktop,
            startmenu,
            uninstaller,
            // 체크 시 등록, 미체크 시 기존 등록 상태를 유지하고 경로만 새 설치본으로 갱신
            if startup { Some(true) } else { None },
            migrate,
            launch,
        );
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/uninstall") {
        let dir = parse_query_str(first_line, "dir")
            .unwrap_or_else(|| default_install_dir().to_string_lossy().to_string());
        let keep_data = parse_query_str(first_line, "keep").unwrap_or_default() == "1";
        let json = perform_uninstall(&dir, keep_data);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/browse_dir") {
        let current = parse_query_str(first_line, "current")
            .unwrap_or_else(|| default_install_dir().to_string_lossy().to_string());
        let body = if let Some(selected) = browse_for_install_folder(&current) {
            format!(r#"{{"ok":true,"path":"{}"}}"#, escape_json(&selected))
        } else {
            r#"{"ok":false}"#.to_string()
        };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/open_dir") {
        let dir = parse_query_str(first_line, "dir")
            .unwrap_or_else(|| default_install_dir().to_string_lossy().to_string());
        let _ = Command::new("explorer.exe").arg(&dir).spawn();
        let body = r#"{"ok":true}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/launch") {
        let dir = parse_query_str(first_line, "dir")
            .unwrap_or_else(|| default_install_dir().to_string_lossy().to_string());
        let exe = PathBuf::from(&dir).join("CoreFlow.exe");
        if exe.exists() {
            let _ = Command::new(&exe)
                .current_dir(&dir)
                .creation_flags(CREATE_NO_WINDOW)
                .spawn();
        }
        let body = r#"{"ok":true}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    } else if first_line.starts_with("POST /api/quit") {
        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
        let _ = stream.write_all(resp.as_bytes());
        let _ = stream.flush();
        thread::sleep(Duration::from_millis(120));
        std::process::exit(0);
    } else {
        let def_dir = default_install_dir();
        let already_installed = def_dir.join("CoreFlow.exe").exists();
        let pkg_mb = format!(
            "{:.2}",
            (EMBEDDED_COREFLOW_EXE.len() + EMBEDDED_ICON_ICO.len()) as f64 / (1024.0 * 1024.0)
        );
        let html = SETUP_HTML
            .replace("__DEFAULT_INSTALL_DIR__", &escape_json(&def_dir.to_string_lossy()))
            .replace("__ALREADY_INSTALLED__", if already_installed { "true" } else { "false" })
            .replace(
                "__INITIAL_UNINSTALL_MODE__",
                if initial_uninstall_mode { "true" } else { "false" },
            )
            .replace("__PACKAGE_SIZE_MB__", &pkg_mb)
            .replace("v1.0.0 Release", concat!("v", env!("CARGO_PKG_VERSION"), " Release"));
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            html.len(),
            html
        );
        let _ = stream.write_all(resp.as_bytes());
    }
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let initial_uninstall_mode = args.iter().any(|a| a == "--uninstall" || a == "/uninstall");
    let silent_update_mode = args.iter().any(|a| a == "--silent-update");
    let already_elevated = args.iter().any(|a| a == "--elevated");
    let custom_dir_arg = args.windows(2).find(|w| w[0] == "--dir").map(|w| w[1].clone());

    // C:\Program Files\CoreFlow 설치를 위해 관리자 권한이 아닌 경우 UAC 권한 상승 요청
    unsafe {
        if IsUserAnAdmin() == 0 && !already_elevated {
            if let Ok(exe) = env::current_exe() {
                let op_w = to_wide_null("runas");
                let exe_w = to_wide_null(&exe.to_string_lossy());
                let mut param_str = String::from("--elevated");
                if initial_uninstall_mode {
                    param_str.push_str(" --uninstall");
                }
                if silent_update_mode {
                    param_str.push_str(" --silent-update");
                }
                if let Some(ref d) = custom_dir_arg {
                    param_str.push_str(&format!(" --dir \"{}\"", d));
                }
                let param_w = to_wide_null(&param_str);
                let cur_dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                let dir_w = to_wide_null(&cur_dir.to_string_lossy());
                let res = ShellExecuteW(
                    0,
                    op_w.as_ptr(),
                    exe_w.as_ptr(),
                    param_w.as_ptr(),
                    dir_w.as_ptr(),
                    1,
                );
                if res > 32 {
                    std::process::exit(0);
                }
            }
        }
    }

    // 자동 업데이트 모드 (--silent-update): GUI 창 없이 즉시 기존 경로(또는 --dir 경로)에 덮어쓰기 업데이트 후 재실행
    if silent_update_mode {
        thread::sleep(Duration::from_millis(600));
        let target_dir = custom_dir_arg
            .unwrap_or_else(|| default_install_dir().to_string_lossy().to_string());
        let _ = perform_install(
            &target_dir,
            true,  // 바탕화면 바로가기 갱신
            true,  // 시작 메뉴 바로가기 갱신
            true,  // 언인스톨러 버전 갱신
            None,  // 자동 실행 설정 유지 (등록돼 있으면 새 경로로 갱신)
            true,  // 기존 사용자 데이터 유지
            true,  // 설치 후 즉시 CoreFlow 실행
        );
        std::process::exit(0);
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind setup port");
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");

    let last_hb = Arc::new(AtomicU64::new(now_secs()));
    let connected = Arc::new(AtomicBool::new(false));

    {
        let hb = Arc::clone(&last_hb);
        let conn = Arc::clone(&connected);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(2));
            let elapsed = now_secs().saturating_sub(hb.load(Ordering::SeqCst));
            if conn.load(Ordering::SeqCst) && elapsed > 10 {
                std::process::exit(0);
            } else if !conn.load(Ordering::SeqCst) && elapsed > 45 {
                std::process::exit(0);
            }
        });
    }

    launch_setup_window(&url);
    spawn_window_icon_applier();

    for stream in listener.incoming().flatten() {
        let hb = Arc::clone(&last_hb);
        let conn = Arc::clone(&connected);
        thread::spawn(move || {
            handle_client(stream, &hb, &conn, initial_uninstall_mode);
        });
    }
}

const SETUP_HTML: &str = r#"<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CoreFlow Setup — 설치 및 관리 마법사</title>
<link rel="icon" type="image/x-icon" href="/favicon.ico">
<style>
  :root {
    --bg-dark: #11141d;
    --bg-card: #1a1f2c;
    --bg-input: #0e1118;
    --brand: #00b4d8;
    --brand-accent: #5865f2;
    --green: #00c875;
    --red: #e53935;
    --text-main: #f2f4f8;
    --text-muted: #949ba4;
    --border: rgba(255, 255, 255, 0.09);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; user-select: none; }
  body {
    font-family: 'Pretendard', 'Malgun Gothic', 'Segoe UI', sans-serif;
    background: radial-gradient(circle at top right, #1d263b 0%, #10131c 65%);
    color: var(--text-main);
    height: 100vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .hero {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 22px 26px 18px;
    background: linear-gradient(135deg, rgba(0, 180, 216, 0.14), rgba(88, 101, 242, 0.12));
    border-bottom: 1px solid var(--border);
  }
  .hero-icon {
    width: 58px;
    height: 58px;
    border-radius: 14px;
    box-shadow: 0 8px 22px rgba(0, 0, 0, 0.45);
    flex-shrink: 0;
  }
  .hero-info { flex: 1; }
  .hero-title {
    font-size: 20px;
    font-weight: 800;
    letter-spacing: -0.3px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .badge {
    font-size: 11px;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 999px;
    background: rgba(0, 180, 216, 0.18);
    color: #56cfe1;
    border: 1px solid rgba(0, 180, 216, 0.35);
  }
  .badge.installed {
    background: rgba(0, 200, 117, 0.16);
    color: var(--green);
    border-color: rgba(0, 200, 117, 0.35);
  }
  .hero-sub {
    font-size: 12.5px;
    color: var(--text-muted);
    margin-top: 4px;
  }
  .content {
    flex: 1;
    padding: 20px 26px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .section-box {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 11px;
    padding: 14px 16px;
  }
  .section-label {
    font-size: 12px;
    font-weight: 700;
    color: #72efdd;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    margin-bottom: 8px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .path-row {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .path-input {
    flex: 1;
    padding: 9px 12px;
    border-radius: 7px;
    border: 1px solid rgba(255, 255, 255, 0.15);
    background: var(--bg-input);
    color: var(--text-main);
    font-family: 'Consolas', monospace;
    font-size: 12.5px;
    outline: none;
  }
  .path-input:focus {
    border-color: var(--brand);
  }
  .btn-browse {
    padding: 9px 14px;
    border-radius: 7px;
    font-size: 12.5px;
    font-weight: 700;
    background: rgba(0, 180, 216, 0.16);
    color: #72efdd;
    border: 1px solid rgba(0, 180, 216, 0.4);
    cursor: pointer;
    white-space: nowrap;
    transition: all 0.15s ease;
  }
  .btn-browse:hover {
    background: rgba(0, 180, 216, 0.28);
  }
  .preset-row {
    display: flex;
    gap: 6px;
    margin-top: 8px;
    flex-wrap: wrap;
  }
  .preset-chip {
    font-size: 11px;
    padding: 3px 9px;
    border-radius: 6px;
    background: rgba(255, 255, 255, 0.05);
    color: var(--text-muted);
    border: 1px solid var(--border);
    cursor: pointer;
    transition: all 0.15s ease;
  }
  .preset-chip:hover {
    color: var(--text-main);
    border-color: rgba(0, 180, 216, 0.45);
    background: rgba(0, 180, 216, 0.1);
  }
  .opt-list {
    display: flex;
    flex-direction: column;
    gap: 9px;
  }
  .opt-item {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 13px;
    cursor: pointer;
  }
  .opt-item input[type="checkbox"] {
    width: 16px;
    height: 16px;
    accent-color: var(--brand);
    cursor: pointer;
  }
  .progress-wrap {
    display: none;
    flex-direction: column;
    gap: 10px;
  }
  .progress-bar-bg {
    width: 100%;
    height: 10px;
    background: var(--bg-input);
    border-radius: 999px;
    overflow: hidden;
  }
  .progress-bar-fill {
    height: 100%;
    width: 0%;
    background: linear-gradient(90deg, #00b4d8, #00c875);
    transition: width 0.25s ease;
  }
  .step-log {
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px 12px;
    font-size: 12px;
    color: #cfd6e0;
    max-height: 145px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 5px;
  }
  .footer {
    padding: 14px 26px;
    background: rgba(12, 15, 22, 0.9);
    border-top: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .btn {
    padding: 9px 18px;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 700;
    border: none;
    cursor: pointer;
    transition: all 0.15s ease;
  }
  .btn-primary {
    background: linear-gradient(135deg, #0096c7, #5865f2);
    color: #fff;
    box-shadow: 0 4px 14px rgba(0, 150, 199, 0.35);
  }
  .btn-primary:hover { filter: brightness(1.1); }
  .btn-secondary {
    background: rgba(255, 255, 255, 0.08);
    color: var(--text-main);
    border: 1px solid var(--border);
  }
  .btn-secondary:hover { background: rgba(255, 255, 255, 0.14); }
  .btn-danger {
    background: rgba(229, 57, 53, 0.16);
    color: #ff6b6b;
    border: 1px solid rgba(229, 57, 53, 0.35);
  }
  .btn-danger:hover { background: rgba(229, 57, 53, 0.28); }
</style>
</head>
<body oncontextmenu="return false;">
  <div class="hero">
    <img src="/favicon.ico" class="hero-icon" alt="CoreFlow">
    <div class="hero-info">
      <div class="hero-title">
        CoreFlow Setup
        <span class="badge">v1.0.0 Release</span>
        <span class="badge installed" id="installed-badge" style="display:none;">설치됨</span>
      </div>
      <div class="hero-sub">
        실시간 하드웨어(CPU/RAM/GPU/네트워크/디스크) & 게이밍 FPS · 플레이 로그 · 미니 HUD 스튜디오
      </div>
    </div>
  </div>

  <div class="content" id="setup-form-view">
    <div class="section-box">
      <div class="section-label">
        <span>📁 설치 폴더 경로 (Install Location)</span>
        <span style="color:var(--text-muted); font-weight:500;">패키지 크기: 약 __PACKAGE_SIZE_MB__ MB</span>
      </div>
      <div class="path-row">
        <input type="text" id="install-dir" class="path-input" value="__DEFAULT_INSTALL_DIR__">
        <button type="button" class="btn-browse" id="btn-browse" onclick="browseInstallDir()">📂 경로 선택...</button>
      </div>
      <div class="preset-row">
        <span class="preset-chip" onclick="setInstallPath('C:\\Program Files\\CoreFlow')">📌 기본 (C:\Program Files\CoreFlow)</span>
        <span class="preset-chip" onclick="setInstallPath('C:\\CoreFlow')">💻 C:\CoreFlow</span>
        <span class="preset-chip" onclick="setInstallPath('D:\\CoreFlow')">💽 D:\CoreFlow</span>
      </div>
    </div>

    <div class="section-box">
      <div class="section-label">
        <span>⚙️ 설치 구성 및 바로가기 옵션</span>
      </div>
      <div class="opt-list">
        <label class="opt-item">
          <input type="checkbox" id="opt-desktop" checked>
          <span>바탕화면에 <strong>CoreFlow</strong> 바로가기 아이콘 생성</span>
        </label>
        <label class="opt-item">
          <input type="checkbox" id="opt-startmenu" checked>
          <span>Windows 시작 메뉴 프로그램 목록에 바로가기 등록</span>
        </label>
        <label class="opt-item">
          <input type="checkbox" id="opt-uninstaller" checked>
          <span>Windows '설치된 앱(프로그램 추가/제거)'에 정식 언인스톨러 등록</span>
        </label>
        <label class="opt-item">
          <input type="checkbox" id="opt-migrate" checked>
          <span>기존 설정 및 게임 플레이 로그(Todo / 스마트 알림 / 게임 기록) 유지·이전</span>
        </label>
        <label class="opt-item">
          <input type="checkbox" id="opt-startup">
          <span>Windows 시작 시 CoreFlow 자동 실행 등록</span>
        </label>
        <label class="opt-item">
          <input type="checkbox" id="opt-launch" checked>
          <span>설치 완료 후 <strong>CoreFlow</strong> 바로 실행</span>
        </label>
      </div>
    </div>

    <div class="section-box progress-wrap" id="progress-box">
      <div class="section-label">
        <span id="progress-title">🚀 설치 진행 상황</span>
        <span id="progress-pct">0%</span>
      </div>
      <div class="progress-bar-bg">
        <div class="progress-bar-fill" id="progress-fill"></div>
      </div>
      <div class="step-log" id="step-log"></div>
    </div>
  </div>

  <div class="footer">
    <div style="display:flex; gap:8px;">
      <button class="btn btn-danger" id="btn-uninstall" onclick="runUninstall()" style="display:none;">🗑️ 프로그램 제거</button>
      <button class="btn btn-secondary" id="btn-open-dir" onclick="openInstallDir()" style="display:none;">📂 설치 폴더 열기</button>
    </div>
    <div style="display:flex; gap:8px;">
      <button class="btn btn-secondary" onclick="quitSetup()">닫기</button>
      <button class="btn btn-primary" id="btn-install" onclick="runInstall()">✨ 지금 설치하기</button>
    </div>
  </div>

<script>
  const alreadyInstalled = __ALREADY_INSTALLED__;
  const initialUninstallMode = __INITIAL_UNINSTALL_MODE__;

  if (alreadyInstalled || initialUninstallMode) {
    document.getElementById('installed-badge').style.display = 'inline-block';
    document.getElementById('btn-uninstall').style.display = 'inline-block';
    document.getElementById('btn-open-dir').style.display = 'inline-block';
    document.getElementById('btn-install').textContent = '🔄 업데이트 / 재설치';
  }

  setInterval(() => {
    fetch('/api/ping').catch(() => {});
  }, 2000);

  window.addEventListener('beforeunload', () => {
    navigator.sendBeacon('/api/quit');
  });

  async function runInstall() {
    const dir = document.getElementById('install-dir').value.trim();
    const desktop = document.getElementById('opt-desktop').checked ? '1' : '0';
    const startmenu = document.getElementById('opt-startmenu').checked ? '1' : '0';
    const uninstaller = document.getElementById('opt-uninstaller').checked ? '1' : '0';
    const migrate = document.getElementById('opt-migrate').checked ? '1' : '0';
    const startup = document.getElementById('opt-startup').checked ? '1' : '0';
    const launch = document.getElementById('opt-launch').checked ? '1' : '0';

    const btn = document.getElementById('btn-install');
    btn.disabled = true;
    btn.textContent = '⏳ 설치 중...';

    const pBox = document.getElementById('progress-box');
    const pFill = document.getElementById('progress-fill');
    const pPct = document.getElementById('progress-pct');
    const pTitle = document.getElementById('progress-title');
    const logEl = document.getElementById('step-log');

    pBox.style.display = 'flex';
    pTitle.textContent = '🚀 CoreFlow 설치 진행 중...';
    pFill.style.width = '35%';
    pPct.textContent = '35%';
    logEl.innerHTML = '<div>• 설치 패키지 검증 및 파일 압축 해제 중...</div>';

    try {
      const qs = `dir=${encodeURIComponent(dir)}&desktop=${desktop}&startmenu=${startmenu}&uninstaller=${uninstaller}&migrate=${migrate}&startup=${startup}&launch=${launch}`;
      const res = await fetch(`/api/install?${qs}`, { method: 'POST' });
      const data = await res.json();
      if (!data.ok) {
        pTitle.textContent = '❌ 설치 오류 발생';
        logEl.innerHTML += `<div style="color:var(--red);">• 오류: ${data.error}</div>`;
        btn.disabled = false;
        btn.textContent = '다시 시도';
        return;
      }

      pFill.style.width = '100%';
      pPct.textContent = '100%';
      pTitle.textContent = '✅ CoreFlow 설치가 완료되었습니다!';
      logEl.innerHTML = (data.steps || []).map(s => `<div style="color:#a8f0c6;">✓ ${s}</div>`).join('');

      document.getElementById('installed-badge').style.display = 'inline-block';
      document.getElementById('btn-uninstall').style.display = 'inline-block';
      document.getElementById('btn-open-dir').style.display = 'inline-block';
      btn.disabled = false;
      btn.textContent = '🚀 CoreFlow 실행 및 닫기';
      btn.onclick = async () => {
        if (launch !== '1') {
          await fetch(`/api/launch?dir=${encodeURIComponent(dir)}`, { method: 'POST' });
        }
        quitSetup();
      };
    } catch (e) {
      pTitle.textContent = '❌ 설치 요청 실패';
      btn.disabled = false;
      btn.textContent = '다시 시도';
    }
  }

  async function runUninstall() {
    const dir = document.getElementById('install-dir').value.trim();
    const keepData = confirm('CoreFlow 프로그램을 제거하시겠습니까?\n\n[확인]을 누르면 제거를 진행합니다.');
    if (!keepData) return;
    const preserveLogs = confirm('기존에 기록된 게임 플레이 로그(logs/)와 Todo/스마트 알림 설정 데이터를 보존하시겠습니까?\n\n• [확인]: 사용자 로그 및 설정 파일 보존\n• [취소]: 모든 데이터까지 완전히 삭제');

    const pBox = document.getElementById('progress-box');
    const pFill = document.getElementById('progress-fill');
    const pPct = document.getElementById('progress-pct');
    const pTitle = document.getElementById('progress-title');
    const logEl = document.getElementById('step-log');

    pBox.style.display = 'flex';
    pTitle.textContent = '🗑️ CoreFlow 제거 진행 중...';
    pFill.style.width = '50%';
    pPct.textContent = '50%';

    const qs = `dir=${encodeURIComponent(dir)}&keep=${preserveLogs ? '1' : '0'}`;
    const res = await fetch(`/api/uninstall?${qs}`, { method: 'POST' });
    const data = await res.json();
    if (data.ok) {
      pFill.style.width = '100%';
      pPct.textContent = '100%';
      pTitle.textContent = '✅ CoreFlow 제거가 완료되었습니다.';
      logEl.innerHTML = (data.steps || []).map(s => `<div>✓ ${s}</div>`).join('');
      document.getElementById('installed-badge').style.display = 'none';
      document.getElementById('btn-uninstall').style.display = 'none';
      document.getElementById('btn-install').textContent = '✨ 지금 설치하기';
    }
  }

  function setInstallPath(path) {
    document.getElementById('install-dir').value = path;
  }

  async function browseInstallDir() {
    const btn = document.getElementById('btn-browse');
    const current = document.getElementById('install-dir').value.trim();
    btn.disabled = true;
    btn.textContent = '📂 폴더 창 열림...';
    try {
      const res = await fetch(`/api/browse_dir?current=${encodeURIComponent(current)}`, { method: 'POST' });
      const data = await res.json();
      if (data.ok && data.path) {
        document.getElementById('install-dir').value = data.path;
      }
    } catch (e) {}
    btn.disabled = false;
    btn.textContent = '📂 경로 선택...';
  }

  function openInstallDir() {
    const dir = document.getElementById('install-dir').value.trim();
    fetch(`/api/open_dir?dir=${encodeURIComponent(dir)}`, { method: 'POST' });
  }

  function quitSetup() {
    fetch('/api/quit', { method: 'POST' }).finally(() => window.close());
  }
</script>
</body>
</html>
"#;
}

#[cfg(windows)]
fn main() {
    win_setup::main();
}
