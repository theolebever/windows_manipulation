use std::{process::abort, ptr::null_mut};

use ntapi::ntpsapi::{NtSetInformationThread, ThreadHideFromDebugger};
use winapi::um::processthreadsapi::GetCurrentThread;

fn disable_debug_events() {
    unsafe {
        let status =
            NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, null_mut(), 0);

        println!("[+]NtSetInformationThread status: {:#02X}", status);

        if status == 0 {
            println!("Successfully disabled debug events.");
        } else {
            abort();
        }
    }
}

fn main() {
    println!("Begin");
    disable_debug_events();
    println!("End");
}
