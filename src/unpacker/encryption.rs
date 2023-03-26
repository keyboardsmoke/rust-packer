use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SCN_MEM_EXECUTE};

#[path = "../shared/mem.rs"]
mod mem;

#[path = "../shared/section.rs"]
mod section;

pub fn initialize()
{
    //
}

pub fn run(_base: u64, module: *mut u8, _peb: u64, dos: IMAGE_DOS_HEADER, nts: IMAGE_NT_HEADERS64) -> anyhow::Result<(), String>
{
    // Static key for now.
    let key: [u8; 3] = [0x50, 0xBE, 0x17];
    println!("Warning: Using static development key.");

    section::foreach_section_module(module, dos, nts, |cs| {
        let good = cs.Characteristics & IMAGE_SCN_MEM_EXECUTE;
        if good != IMAGE_SCN_MEM_EXECUTE {
            return false;
        }

        // Keep going, though.
        if cs.SizeOfRawData == 0 {
            return false;
        }

        unsafe {
            println!("Unpacking section {}", String::from_utf8_unchecked(cs.Name.to_vec()));
        }

        let start = cs.VirtualAddress as usize;
        let end = start + cs.SizeOfRawData as usize;
        let code_base = unsafe { module.offset(cs.VirtualAddress as isize) };

        let qs = unsafe { region::protect(code_base, cs.SizeOfRawData as usize, region::Protection::READ_WRITE_EXECUTE) };
        if qs.is_err() {
            println!("Unable to protect memory at offset 0x{:X}", cs.VirtualAddress);
            return false;
        }

        // Everything works but this. Lol.
        for i in start .. end as usize {
            let key_index = i - start;
            let kv = key[key_index.rem_euclid(key.len())];
            unsafe {
                let base: *mut u8 = module.add(i);
                *base = *base ^ kv;
            };
        }

        // Set it back to normal
        let fr = unsafe { region::protect(code_base, cs.SizeOfRawData as usize, region::Protection::READ_EXECUTE) };
        if fr.is_err() {
            println!("Unable to reset memory protection at offset 0x{:X}", cs.VirtualAddress);
            return false;
        }

        return false;
    });
    Ok(())
}