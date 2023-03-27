use exe::PE;

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

    let pe = unsafe { exe::pe::PtrPE::from_memory(std::mem::transmute::<u64, *mut u8>(base)) }?;
    let dos = pe.get_valid_dos_header()?;

    if dos.e_magic.ne(&exe::DOS_SIGNATURE) {
        println!("Invalid DOS signature. {}", dos.e_magic);
        return Err(anyhow::Error::msg("Invalid DOS signature."));
    }

    let nts = pe.get_nt_headers_64()?;

    if nts.signature.ne(&exe::NT_SIGNATURE) {
        println!("Invalid NT Signature. 0x{:X}", nts.signature);
        return Err(anyhow::Error::msg("Invalid NT signature."));
    }

    // Pass it.
    encryption::run(base, pe.clone(), peb, dos, nts)?;
    
    Ok(())
}