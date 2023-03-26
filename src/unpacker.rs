use winapi::um::winnt::{IMAGE_NT_HEADERS64, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE};

mod encryption;

#[path = "shared/mem.rs"]
mod mem;

pub fn initialize()
{
    encryption::initialize();
}

pub fn run(base: u64, peb: u64) -> anyhow::Result<(), String>
{
    println!("unpacker::run(0x{:X}, 0x{:X})", base, peb);

    let module = unsafe { std::mem::transmute::<u64, *mut u8>(base) };

    let dos: IMAGE_DOS_HEADER = mem::cast_offset_from_mod::<IMAGE_DOS_HEADER>(module, 0);
    
    if dos.e_magic.ne(&IMAGE_DOS_SIGNATURE) {
        println!("Invalid DOS signature. {}", dos.e_magic);
        return Err("Invalid DOS signature.".to_string());
    }

    println!("NT offset 0x{:X}", dos.e_lfanew);

    let ntstart = dos.e_lfanew as usize;
    let nts: IMAGE_NT_HEADERS64 = mem::cast_offset_from_mod::<IMAGE_NT_HEADERS64>(module, ntstart);

    if nts.Signature.ne(&IMAGE_NT_SIGNATURE) {
        println!("Invalid NT Signature. 0x{:X}", nts.Signature);
        return Err("Invalid NT signature.".to_string());
    }

    // Pass it.
    encryption::run(base, module, peb, dos, nts)?;
    
    Ok(())
}