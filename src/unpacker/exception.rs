use shared::metadata::RuntimeFunction;
use std::{collections::HashMap, ffi::c_void, sync::{Mutex}, ops::Index};
use exe::PE;
use winapi::{shared::{ntdef::{PVOID}, basetsd::DWORD64}, um::{winnt::{PRUNTIME_FUNCTION, RUNTIME_FUNCTION, IMAGE_RUNTIME_FUNCTION_ENTRY_u, PGET_RUNTIME_FUNCTION_CALLBACK, IMAGE_RUNTIME_FUNCTION_ENTRY, MEM_COMMIT, PAGE_READWRITE, _IMAGE_RUNTIME_FUNCTION_ENTRY}}};

lazy_static::lazy_static! {
    static ref HASH_DATA: Mutex<HashMap<u32, RUNTIME_FUNCTION>> = Mutex::new(HashMap::new());
}

struct ImmutableDataContext
{
    base: u64,
    size: u64,
    fns: Vec<RuntimeFunction>
}

unsafe extern "C" fn table_callback(controlpc: DWORD64, context: PVOID) -> PRUNTIME_FUNCTION
{
    let ctx_ptr: *mut ImmutableDataContext = context as *mut ImmutableDataContext;
    let ctx = ctx_ptr.as_mut().unwrap();

    let hash_map_res = HASH_DATA.lock();
    if hash_map_res.is_err() {
        println!("Unable to get mutex protected hash map mutable reference.");
        return 0 as PRUNTIME_FUNCTION;
    }

    let mut hash_map = hash_map_res.unwrap();

    println!("ControlPc: 0x{:X}, Base: 0x{:X}, Size: 0x{:X}", controlpc, ctx.base, ctx.size);

    if !(controlpc >= ctx.base && controlpc < (ctx.base + ctx.size)) {
        println!("Unhandled exception....");
        return 0 as PRUNTIME_FUNCTION;
    }

    let cpc = controlpc as u32 - ctx.base as u32;

    match hash_map.get_mut(&cpc) {
        // The value is cached we can just use that.
        Some(v) => {
            println!("Found cached entry for {}", cpc);
            return v as *mut IMAGE_RUNTIME_FUNCTION_ENTRY;
        },
        None => {
            println!("Cached entry not found for {}, inserting...", cpc);
            for i in 0..ctx.fns.len() {
                let x = ctx.fns.index(i);
                let begin = x.get_begin_addr();
                let end = x.get_end_addr();
                println!("Comparing PC 0x{:X} to begin 0x{:X}, end 0x{:X}", cpc, begin, end);
                if cpc >= begin && cpc < end {
                    let mut p: IMAGE_RUNTIME_FUNCTION_ENTRY_u = std::mem::zeroed();
                    *p.UnwindInfoAddress_mut() = x.get_unwind_addr();
                    let rtf = RUNTIME_FUNCTION {
                        BeginAddress: x.get_begin_addr(),
                        EndAddress: x.get_end_addr(),
                        u: p
                    };
                    hash_map.insert(cpc, rtf);
                    println!("Inserted cache entry for 0x{:X}", cpc);
                    break;
                }
            }
        }
    }

    match hash_map.get_mut(&cpc) {
        Some(v) => {
            println!("Finally found cached entry for 0x{:X}", cpc);
            return v as *mut IMAGE_RUNTIME_FUNCTION_ENTRY;
        },
        None => {
            println!("ERROR: We should have a cache entry but we cannot retrieve it.");
            // null if not found...
            return 0 as PRUNTIME_FUNCTION
        }
    }
    // 0 as PRUNTIME_FUNCTION
}

fn get_identifier(base: u64) -> u64
{
    return base | 0x03;
}

pub fn attach(_base: u64, _pe: &mut exe::pe::PtrPE) -> anyhow::Result<(), anyhow::Error>
{
    Ok(())
}

pub fn entry(_base: u64, pe: &mut exe::pe::PtrPE, _peb: u64, metadata: &shared::metadata::Metadata) -> anyhow::Result<(), anyhow::Error>
{
    let img = pe.get_image_base()?;
    let msize = pe.calculate_memory_size()?;

    let imm_alloc = unsafe { windows_sys::Win32::System::Memory::VirtualAlloc(0 as *const c_void, std::mem::size_of::<ImmutableDataContext>(), MEM_COMMIT, PAGE_READWRITE) };
    if imm_alloc.is_null() {
        return Err(anyhow::Error::msg("Unable to allocate context data for function table callback."));
    }

    let imm = imm_alloc as *mut ImmutableDataContext;

    // These won't ever get updated unlike the hash table.
    unsafe {
        // That I still can't do this safely bothers me deeply
        // Still, though, at this stage in the process we don't have to worry much about thread safety
        (*imm).base = img;
        (*imm).size = msize as u64;
        (*imm).fns = metadata.exception_entries.clone();
    }

    let cb: PGET_RUNTIME_FUNCTION_CALLBACK = Some(table_callback);
    let res = unsafe { winapi::um::winnt::RtlInstallFunctionTableCallback(get_identifier(img), img, msize as u32, cb, imm_alloc, 0 as *const u16) };
    if res == 0 {
        println!("Failed to install function table callback with offset 0x{:X} and size 0x{:X} (end: 0x{:X})", img, msize, img + msize as u64);   
    } else {
        println!("Installed function table callback at offset 0x{:X} and size 0x{:X} (end: 0x{:X})", img, msize, img + msize as u64);
    }
    Ok(())
}

pub fn call(_base: u64, _pe: &mut exe::pe::PtrPE) -> anyhow::Result<(), anyhow::Error>
{
    Ok(())
}

pub fn detach(_base: u64, pe: &mut exe::pe::PtrPE) -> anyhow::Result<(), anyhow::Error>
{
    let img = pe.get_image_base()?;
    // A pointer to an array of function entries that were previously passed to RtlAddFunctionTable or an identifier previously passed to RtlInstallFunctionTableCallback. For a definition of the PRUNTIME_FUNCTION type, see WinNT.h.
    unsafe { winapi::um::winnt::RtlDeleteFunctionTable(get_identifier(img) as *mut _IMAGE_RUNTIME_FUNCTION_ENTRY) };
    Ok(())
}