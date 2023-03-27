use std::borrow::BorrowMut;

use exe::{ImageDOSHeader, ImageNTHeaders64};

#[path = "../shared/mem.rs"]
mod mem;

#[path = "../shared/section.rs"]
mod section;

pub fn initialize()
{
    //
}

pub fn run(_base: u64, mut pe: exe::pe::PtrPE, _peb: u64, dos: &ImageDOSHeader, nts: &ImageNTHeaders64) -> anyhow::Result<(), anyhow::Error>
{
    // Static key for now.
    let key: [u8; 3] = [0x50, 0xBE, 0x17];
    println!("Warning: Using static development key.");

    section::foreach_section_module(pe.borrow_mut(), *dos, *nts, |ptr, sec| {
        let s = sec.first().unwrap();

        let good = s.characteristics.bits() & exe::headers::SectionCharacteristics::MEM_EXECUTE.bits();
        if good != exe::headers::SectionCharacteristics::MEM_EXECUTE.bits() {
            return false;
        }

        if s.size_of_raw_data == 0 {
            return false;
        }
    
        let start: usize = s.pointer_to_raw_data.into();
        let end = start + s.size_of_raw_data as usize;

        for i in start .. end as usize {
            let key_index = i - start;
            let kv = key[key_index.rem_euclid(key.len())];
            unsafe {
                let base: *mut u8 = ptr.add(i);
                *base = *base ^ kv;
            };
        }
        return false;
    });
    Ok(())
}