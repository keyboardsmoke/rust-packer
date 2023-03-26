use winapi::um::winnt::{IMAGE_NT_HEADERS64, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE};

mod encryption;

#[path = "shared/mem.rs"]
mod mem;

pub fn initialize()
{
    encryption::initialize();
}

pub fn run(base: u64, peb: u64) -> Result<(), String>
{
    let module = unsafe { std::mem::transmute::<u64, *mut u8>(base) };

    let dos: IMAGE_DOS_HEADER = mem::cast_offset_from_mod::<IMAGE_DOS_HEADER>(module, 0);
    
    if dos.e_magic.ne(&IMAGE_DOS_SIGNATURE) {
        return Err("Invalid DOS signature.".to_string());
    }

    let ntstart = dos.e_lfanew as usize;
    let nts: IMAGE_NT_HEADERS64 = mem::cast_offset_from_mod::<IMAGE_NT_HEADERS64>(module, ntstart);

    if nts.Signature.ne(&IMAGE_NT_SIGNATURE) {
        return Err("Invalid NT signature.".to_string());
    }

    // Pass it.
    encryption::run(base, module, peb, dos, nts)?;
    
    Ok(())
}