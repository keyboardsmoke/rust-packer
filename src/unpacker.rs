use exe::PtrPE;

mod encryption;
mod exception;

fn get_pe(base: u64) -> anyhow::Result<PtrPE, anyhow::Error>
{
    let per = unsafe { exe::pe::PtrPE::from_memory(std::mem::transmute::<u64, *mut u8>(base)) };
    if per.is_err() {
        return Err(anyhow::Error::msg("Unable to open memory."));
    }

    let pe = per.ok().ok_or(anyhow::Error::msg("Unable to open memory."))?;
    Ok(pe)
}

pub fn attach(base: u64) -> anyhow::Result<(), anyhow::Error>
{
    println!("unpacker::attach(0x{:X})", base);

    let mut pe = get_pe(base)?;
    encryption::attach(base, &mut pe)?;
    exception::attach(base, &mut pe)?;
    Ok(())
}

pub fn entry(base: u64, peb: u64) -> anyhow::Result<(), anyhow::Error>
{
    println!("unpacker::entry(0x{:X}, 0x{:X})", base, peb);

    let mut pe = get_pe(base)?;
    let meta = shared::metadata::read_data(&mut pe)?;

    encryption::entry(base, &mut pe, peb, &meta)?;
    exception::entry(base, &mut pe, peb, &meta)?;

    Ok(())
}

pub fn call(base: u64) -> anyhow::Result<(), anyhow::Error>
{
    println!("unpacker::call(0x{:X})", base);

    let mut pe = get_pe(base)?;
    encryption::call(base, &mut pe)?;
    exception::call(base, &mut pe)?;
    Ok(())
}

pub fn detach(base: u64) -> anyhow::Result<(), anyhow::Error>
{
    println!("unpacker::detach(0x{:X})", base);

    let mut pe = get_pe(base)?;
    encryption::detach(base, &mut pe)?;
    exception::detach(base, &mut pe)?;
    Ok(())
}