mod encryption;
mod exception;

pub fn initialize() -> anyhow::Result<(), anyhow::Error>
{
    encryption::initialize()?;
    exception::initialize()?;
    Ok(())
}

pub fn run(base: u64, peb: u64) -> anyhow::Result<(), anyhow::Error>
{
    println!("unpacker::run(0x{:X}, 0x{:X})", base, peb);

    let per = unsafe { exe::pe::PtrPE::from_memory(std::mem::transmute::<u64, *mut u8>(base)) };
    if per.is_err() {
        return Err(anyhow::Error::msg("Unable to open memory."));
    }

    let mut pe = per.ok().ok_or(anyhow::Error::msg("Unable to open memory."))?;

    let meta = shared::metadata::read_data(&mut pe)?;

    // Pass it.
    encryption::run(base, &mut pe, peb, &meta)?;
    exception::run(base, &mut pe, peb, &meta)?;

    Ok(())
}