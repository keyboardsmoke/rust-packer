use winapi::{um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SCN_MEM_EXECUTE}};

#[path = "../shared/mem.rs"]
mod mem;

#[path = "../shared/section.rs"]
mod section;

pub fn pack(buffer: &mut Vec<u8>, dos: IMAGE_DOS_HEADER, nts: IMAGE_NT_HEADERS64) -> anyhow::Result<(), String>
{
    // Static key for now.
    let key: [u8; 3] = [0x50, 0xBE, 0x17];
    println!("Warning: Using static development key.");

    section::foreach_section_buffer(buffer, dos, nts, |buf, sec| {
        let good = sec.Characteristics & IMAGE_SCN_MEM_EXECUTE;
        if good != IMAGE_SCN_MEM_EXECUTE {
            return false;
        }

        if sec.SizeOfRawData == 0 {
            return false;
        }
    
        let start = sec.PointerToRawData as usize;
        let end = start + sec.SizeOfRawData as usize;
    
        buf[start .. end]
            .iter_mut()
            .enumerate()
            .for_each(|(i, byte)| {
                let kv = key[i.rem_euclid(key.len())];
                *byte = *byte ^ kv;
            });
        return false;
    });
    Ok(())
}