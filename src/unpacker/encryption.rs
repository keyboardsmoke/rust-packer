use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SCN_MEM_EXECUTE};

#[path = "../shared/mem.rs"]
mod mem;

#[path = "../shared/section.rs"]
mod section;

pub fn initialize()
{
    //
}

pub fn run(_base: u64, module: *mut u8, _peb: u64, dos: IMAGE_DOS_HEADER, nts: IMAGE_NT_HEADERS64) -> Result<(), String>
{
    // Static key for now.
    let key: [u8; 3] = [0x50, 0xBE, 0x17];
    println!("Warning: Using static development key.");

    section::foreach_section_module(module, dos, nts, |cs| {
        let good = cs.Characteristics & IMAGE_SCN_MEM_EXECUTE;
        if good != IMAGE_SCN_MEM_EXECUTE {
            return false;
        }

        let start = cs.PointerToRawData as usize;
        let end = cs.SizeOfRawData as usize;
    
        for i in start .. end {
            let kv = key[i.rem_euclid(key.len())];
            unsafe {
                let base = module.offset(i as isize);
                *base = *base ^ kv;
            };
        }
        return false;
    });
    Ok(())
}