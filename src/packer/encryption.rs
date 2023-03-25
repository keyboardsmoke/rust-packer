use winapi::{um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_FILE_HEADER, IMAGE_SECTION_HEADER, IMAGE_SCN_MEM_EXECUTE}, shared::basetsd::DWORD32};

use crate::packer::cast_offset;

fn encrypt_section_with_key(buffer: &mut Vec<u8>, key: Vec<u8>, sec: IMAGE_SECTION_HEADER) -> Result<(), String>
{
    // We only want to encrypt executable sections here, makes it easier.
    let good = sec.Characteristics & IMAGE_SCN_MEM_EXECUTE;
    if good != IMAGE_SCN_MEM_EXECUTE {
        return Ok(());
    }

    let start = sec.PointerToRawData as usize;
    let end = sec.SizeOfRawData as usize;

    buffer[start .. end]
        .iter_mut()
        .enumerate()
        .for_each(|(i, byte)| {
            let kv = key[i.rem_euclid(key.len())];
            *byte = *byte ^ kv;
        });
    Ok(())
}

pub fn pack(buffer: &mut Vec<u8>, dos: IMAGE_DOS_HEADER, nts: IMAGE_NT_HEADERS64) -> Result<(), String>
{
    // Static key for now.
    let key: [u8; 3] = [0x50, 0xBE, 0x17];
    println!("Warning: Using static development key.");

    // field_offset of OptionalHeader + size
    let section_base = dos.e_lfanew as usize + core::mem::size_of::<DWORD32>() + core::mem::size_of::<IMAGE_FILE_HEADER>() + nts.FileHeader.SizeOfOptionalHeader as usize;

    println!("Section Base {}", section_base);

    for i in 0 .. nts.FileHeader.NumberOfSections
    {
        println!("Accessing section index {}", i);
        let offset = i as usize * core::mem::size_of::<IMAGE_SECTION_HEADER>();
        let sec = cast_offset::<IMAGE_SECTION_HEADER>(&buffer, section_base + offset);
        let section_name: String = std::str::from_utf8(&sec.Name).unwrap().to_string();
        println!("Section name: {}", section_name);
        if encrypt_section_with_key(buffer, key.to_vec(), sec).is_ok() {
            println!("Encrypted section {}", section_name); 
        }
    }
    Ok(())
}