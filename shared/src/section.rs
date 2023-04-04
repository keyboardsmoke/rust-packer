use exe::{ImageSectionHeader, ImageNTHeaders64, ImageDOSHeader, Address, PE, Buffer, ImageFileHeader, CCharString, SectionCharacteristics};

use crate::mem;

#[allow(unused)]
pub fn foreach_section_buffer<T: FnMut(*mut u8, &ImageSectionHeader)>(pe: &mut exe::pe::VecPE, dos: ImageDOSHeader, nts: ImageNTHeaders64, mut cb: T) -> bool
{
    let nts_base: usize = dos.e_lfanew.as_offset(pe).unwrap().into();
    let section_base = nts_base as usize + core::mem::size_of::<u32>() + core::mem::size_of::<ImageFileHeader>() + nts.file_header.size_of_optional_header as usize;

    let peb = pe.as_mut_ptr();
    pe.get_section_table().iter().for_each(|sec| {
        sec.iter().for_each(|sec| {
            let v = sec;
            let sec_name = v.name.as_str().unwrap();
            println!("Section Iter {}", sec_name);
            cb(peb, v);
        });
    });
    return false;
}

#[allow(unused)]
pub fn foreach_section_module<T: FnMut(*mut u8, &ImageSectionHeader)>(pe: &mut exe::pe::PtrPE, dos: ImageDOSHeader, nts: ImageNTHeaders64, mut cb: T) -> bool
{
    let nts_base: usize = dos.e_lfanew.as_offset(pe).unwrap().into();
    let section_base = nts_base as usize + core::mem::size_of::<u32>() + core::mem::size_of::<ImageFileHeader>() + nts.file_header.size_of_optional_header as usize;
    let peb = pe.as_mut_ptr();
    pe.get_section_table().iter().for_each(|sec| {
        sec.iter().for_each(|sec| {
            cb(peb, sec);
        });
    });
    return false;
}

#[allow(unused)]
pub fn add_section_with_data(pe: &mut exe::pe::VecPE, name: &str, data: Vec<u8>) -> anyhow::Result<(), anyhow::Error>
{
    let size_of_data_unaligned = data.len();
    let size_of_data_aligned = mem::page_align(size_of_data_unaligned);

    println!("Size of data = 0x{:X}", size_of_data_unaligned);
    println!("Page aligned size of data = 0x{:X}", size_of_data_aligned);

    let mut new_data = data.clone();

    let remainder = size_of_data_aligned - size_of_data_unaligned;
    if remainder > 0 {
        let mut total_section_data = (0..remainder).map(|_|0).collect::<Vec<u8>>();
        new_data.append(&mut total_section_data);
    }

    // Append the data immediately.
    pe.get_mut_buffer().append(new_data);

    let chars = SectionCharacteristics::MEM_READ | SectionCharacteristics::ALIGN_4096BYTES | SectionCharacteristics::CNT_INITIALIZED_DATA;

    let mut namebuf = Vec::<exe::CChar>::with_capacity(8);
    let name_bytes = name.as_bytes();

    for i in 0..8 {
        if i < name.len() {
            namebuf.push(exe::CChar(name_bytes[i]));
        } else {
            namebuf.push(exe::CChar(0));
        }
    }

    let boxed_name: Box<[exe::CChar; 8]> = match namebuf.into_boxed_slice().try_into() {
        Ok(ba) => ba,
        Err(o) => panic!("Expected a Vec of length {} but it was {}", 8, o.len()),
    };

    let new_hdr = ImageSectionHeader { 
        name: *boxed_name, 
        virtual_size: size_of_data_aligned as u32, 
        virtual_address: exe::RVA(0), 
        size_of_raw_data: size_of_data_aligned as u32, 
        pointer_to_raw_data: exe::Offset(0), 
        pointer_to_relocations: exe::Offset(0), 
        pointer_to_linenumbers: exe::Offset(0), 
        number_of_relocations: 0, 
        number_of_linenumbers: 0, 
        characteristics: chars
    };

    pe.append_section(&new_hdr)?;
    pe.fix_image_size()?;
    Ok(())
}