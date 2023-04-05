#![cfg(windows)]

mod unpacker;

use winapi::shared::ntdef::NULL;
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::winnt::{CONTEXT, DLL_PROCESS_DETACH, DLL_PROCESS_ATTACH};
use winapi::shared::minwindef::{TRUE, BOOL, DWORD, HINSTANCE};

static mut OEP: u64 = 0;

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: DWORD, reserved: *mut CONTEXT) -> BOOL
{
    let base = unsafe { GetModuleHandleA(NULL as *const i8) as u64 };

    if call_reason == DLL_PROCESS_ATTACH {
        println!("DLL_PROCESS_ATTACH");
        
        // Call initialization stuff
        if unpacker::attach(base).is_err() {
            println!("unpacker attach failed.");
        } else {
            unsafe { 
                OEP = (*reserved).Rip;
                (*reserved).Rip = startup_hijack as u64; 
            }
        }
    }
    else if call_reason == DLL_PROCESS_DETACH {
        if unpacker::detach(base).is_err() {
            println!("unpacker detach failed.");
        }
    }
    return TRUE;
}

#[no_mangle]
fn p()
{
    let base = unsafe { GetModuleHandleA(NULL as *const i8) as u64 };
    if unpacker::call(base).is_err() {
        println!("unpacker call failed.");
    }
}

fn startup_hijack(peb_ptr: u64) -> u32
{
    // Run all modules...
    let base = unsafe { GetModuleHandleA(NULL as *const i8) as u64 };
    let res = unpacker::entry(base, peb_ptr);
    if res.is_err()
    {
        panic!("unpacker entry failed.");
    }
    else 
    {
        unsafe { 
            let original_entry_point: extern "C" fn(u64) -> u32 = std::mem::transmute(OEP);
            return original_entry_point(peb_ptr);
        }
    }
}