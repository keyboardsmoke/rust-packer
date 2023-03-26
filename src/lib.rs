#![cfg(windows)]
//#![no_builtins]

mod unpacker;

use winapi::shared::ntdef::NULL;
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::winnt::{CONTEXT};
use winapi::shared::minwindef::{TRUE, BOOL, DWORD, HINSTANCE};

static mut OEP: u64 = 0;

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: DWORD, reserved: *mut CONTEXT) -> BOOL
{
    const DLL_PROCESS_ATTACH: DWORD = 1;

    if call_reason == DLL_PROCESS_ATTACH {
        println!("packer initialization called.");
        
        // Call initialization stuff
        unpacker::initialize();

        unsafe { 
            OEP = (*reserved).Rip;
            (*reserved).Rip = startup_hijack as u64; 
        }
    }
    return TRUE;
}

#[no_mangle]
fn p()
{
    // This function only exists to be exported and imported by the target
    // Once this library is imported, ntdll will naturally feed the context into the reserved parameter
}

fn startup_hijack(peb_ptr: u64) -> u32
{
    // Run all modules...
    let base = unsafe { GetModuleHandleA(NULL as *const i8) as u64 };
    let res = unpacker::run(base, peb_ptr);
    if res.is_err()
    {
        println!("Nope.");
    } 
    else 
    {
        unsafe { 
            let original_entry_point: extern "C" fn(u64) -> u32 = std::mem::transmute(OEP);
            return original_entry_point(peb_ptr);
        }
    }
    return 0;
}