use std::{borrow::BorrowMut};

use exe::{ImageDOSHeader, ImageNTHeaders64, PE};

#[path = "../shared/mem.rs"]
mod mem;

#[path = "../shared/section.rs"]
mod section;

pub fn initialize()
{
    todo!("Nothing here yet.");
}

pub fn run(_base: u64, mut pe: exe::pe::PtrPE, _peb: u64, dos: &ImageDOSHeader, nts: &ImageNTHeaders64) -> anyhow::Result<(), anyhow::Error>
{
    let pack_section_hdr = pe.get_section_by_name(".pack")?;
    let pack_section_data = pack_section_hdr.read(&pe)?;
    let pack_section_vec = pack_section_data.to_vec();

    let mut spl = pack_section_vec.split(|num| *num == 0);
    let key_split = spl.next().ok_or(anyhow::Error::msg("Unable to find key data in section"))?;

    print!("Pack key read [");
    for i in 0..key_split.len() {
        print!("{:X}", key_split[i]);
    }
    println!("]");

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
            let kv = key_split[key_index.rem_euclid(key_split.len())];
            unsafe {
                let base: *mut u8 = ptr.add(i);
                *base = *base ^ kv;
            };
        }
        return false;
    });
    Ok(())
}