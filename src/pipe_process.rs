extern crate winapi;

use std::ffi::OsStr;
use std::io::{self, Read};
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use winapi::shared::minwindef::{DWORD, FALSE, LPVOID, TRUE};
use winapi::shared::ntdef::HANDLE;
use winapi::um::fileapi::{ReadFile};
use winapi::um::handleapi::{CloseHandle, SetHandleInformation};
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::namedpipeapi::CreatePipe;
use winapi::um::processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::HANDLE_FLAG_INHERIT;
use winapi::um::winbase::{CREATE_UNICODE_ENVIRONMENT, INFINITE, STARTF_USESTDHANDLES};

fn main() -> io::Result<()> {
    unsafe {
        let mut sa_attr: SECURITY_ATTRIBUTES = std::mem::zeroed();
        sa_attr.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as DWORD;
        sa_attr.bInheritHandle = TRUE;
        sa_attr.lpSecurityDescriptor = null_mut();

        let mut h_child_stdout_rd: HANDLE = null_mut();
        let mut h_child_stdout_wr: HANDLE = null_mut();

        if CreatePipe(
            &mut h_child_stdout_rd,
            &mut h_child_stdout_wr,
            &mut sa_attr,
            0,
        ) == FALSE
        {
            eprintln!("Stdout pipe creation failed");
            return Err(io::Error::last_os_error());
        }

        if SetHandleInformation(h_child_stdout_rd, HANDLE_FLAG_INHERIT, 0) == FALSE {
            eprintln!("SetHandleInformation failed");
            return Err(io::Error::last_os_error());
        }

        let mut si_start_info: STARTUPINFOW = std::mem::zeroed();
        let mut pi_proc_info: PROCESS_INFORMATION = std::mem::zeroed();

        si_start_info.cb = std::mem::size_of::<STARTUPINFOW>() as DWORD;
        si_start_info.hStdError = h_child_stdout_wr;
        si_start_info.hStdOutput = h_child_stdout_wr;
        si_start_info.dwFlags |= STARTF_USESTDHANDLES;

        let mut cmd = OsStr::new("powershell.exe -Command \"Get-Process\"")
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<u16>>();

        if CreateProcessW(
            null(),
            cmd.as_mut_ptr(),
            null_mut(),
            null_mut(),
            TRUE,
            CREATE_UNICODE_ENVIRONMENT,
            null_mut(),
            null_mut(),
            &mut si_start_info,
            &mut pi_proc_info,
        ) == 0
        {
            eprintln!("CreateProcessW failed");
            return Err(io::Error::last_os_error());
        }
        CloseHandle(h_child_stdout_wr);

        let mut buffer: [u8; 4096] = [0; 4096];
        let mut dw_read: DWORD = 0;
        let mut b_success: i32;

        loop {
            b_success = ReadFile(
                h_child_stdout_rd,
                buffer.as_mut_ptr() as LPVOID,
                buffer.len() as DWORD,
                &mut dw_read,
                null_mut(),
            );
            if b_success == FALSE || dw_read == 0 {
                break;
            }
            println!("{}", String::from_utf8_lossy(&buffer[..dw_read as usize]));
        }

        CloseHandle(h_child_stdout_rd);
        WaitForSingleObject(pi_proc_info.hProcess, INFINITE);
        CloseHandle(pi_proc_info.hProcess);
        CloseHandle(pi_proc_info.hThread);
    }

    Ok(())
}
