mod encryption;

#[path = "shared/mem.rs"]
mod mem;

pub fn initialize()
{
    encryption::initialize();
}

pub fn run(base: u64, peb: u64) -> anyhow::Result<(), anyhow::Error>
{
    println!("unpacker::run(0x{:X}, 0x{:X})", base, peb);

    let per = unsafe { exe::pe::PtrPE::from_memory(std::mem::transmute::<u64, *mut u8>(base)) };
    if per.is_err() {
        return Err(anyhow::Error::msg("Unable to open memory."));
    }

    let mut pe = per.ok().ok_or(anyhow::Error::msg("Unable to open memory."))?;

    // Pass it.
    encryption::run(base, &mut pe, peb)?;
    
    Ok(())
}