use std::{collections::HashMap, ffi::c_void, ops::Index};
use exe::PE;
use once_cell::sync::Lazy;
use winapi::{shared::{ntdef::{PVOID}, basetsd::DWORD64}, um::{winnt::{PRUNTIME_FUNCTION, RUNTIME_FUNCTION, IMAGE_RUNTIME_FUNCTION_ENTRY_u, PGET_RUNTIME_FUNCTION_CALLBACK}}};

static mut CBD: shared::metadata::FunctionTableCallbackData = shared::metadata::FunctionTableCallbackData {base: 0, size: 0, fns: Vec::new(), rts: Lazy::new(|| HashMap::new()) };

unsafe extern "C" fn table_callback(controlpc: DWORD64, _context: PVOID) -> PRUNTIME_FUNCTION
{
    println!("ControlPc: 0x{:X}, Base: 0x{:X}, Size: 0x{:X}", controlpc, CBD.base, CBD.size);

    if !(controlpc >= CBD.base && controlpc < (CBD.base + CBD.size)) {
        println!("Unhandled exception....");
        return 0 as PRUNTIME_FUNCTION;
    }

    let cpc = controlpc as u32 - CBD.base as u32;

    match CBD.rts.get(&cpc) {
        // The value is cached we can just use that.
        Some(v) => {
            println!("Found cached entry for {}", cpc);
            return *v;
        },
        None => {
            println!("Cached entry not found for {}, inserting...", cpc);
            for i in 0..CBD.fns.len() {
                let x = CBD.fns.index(i);
                let begin = x.get_begin_addr();
                let end = x.get_end_addr();
                println!("Comparing PC 0x{:X} to begin 0x{:X}, end 0x{:X}", cpc, begin, end);
                if cpc >= begin && cpc < end {
                    let mut p: IMAGE_RUNTIME_FUNCTION_ENTRY_u = std::mem::zeroed();
                    *p.UnwindInfoAddress_mut() = x.get_unwind_addr();
                    let mut rtf = RUNTIME_FUNCTION {
                        BeginAddress: x.get_begin_addr(),
                        EndAddress: x.get_end_addr(),
                        u: p
                    };
                    CBD.rts.insert(cpc, &mut rtf);
                    println!("Inserted cache entry for 0x{:X}", cpc);
                    break;
                }
            }
        }
    }

    match CBD.rts.get(&cpc) {
        Some(v) => {
            println!("Finally found cached entry for 0x{:X}", cpc);
            return *v;
        },
        None => {
            println!("ERROR: We should have a cache entry but we cannot retrieve it.");
            // null if not found...
            return 0 as PRUNTIME_FUNCTION
        }
    }
    // 0 as PRUNTIME_FUNCTION
}

pub fn initialize() -> anyhow::Result<(), anyhow::Error>
{
    Ok(())
}

pub fn run(_base: u64, pe: &mut exe::pe::PtrPE, _peb: u64, metadata: &shared::metadata::Metadata) -> anyhow::Result<(), anyhow::Error>
{
    let img = pe.get_image_base()?;
    let msize = pe.calculate_memory_size()?;

    // Need something better than this static global, it's annoying.
    // The problem is, anything we pass to context below has to be a pointer and globally allocated
    // basically, unsafe by default as it must extend beyond the lifetime of this call.
    // As I said, extremely annoying.
    unsafe { 
        CBD.fns = metadata.exception_entries.clone();
        CBD.base = img;
        CBD.size = msize as u64;
    };

    let cb: PGET_RUNTIME_FUNCTION_CALLBACK = Some(table_callback);
    let res = unsafe { winapi::um::winnt::RtlInstallFunctionTableCallback(img | 0x03, img, msize as u32, cb, 0 as *mut c_void, 0 as *const u16) };
    if res == 0 {
        println!("Failed to install function table callback with offset 0x{:X} and size 0x{:X} (end: 0x{:X})", img, msize, img + msize as u64);   
    } else {
        println!("Installed function table callback at offset 0x{:X} and size 0x{:X} (end: 0x{:X})", img, msize, img + msize as u64);
    }
    Ok(())
}